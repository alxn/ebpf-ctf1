// SPDX-License-Identifier: (GPL-2.0 OR MIT)
/* Copyright (C) 2021 Isovalent */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "bpf_helpers.h"

#define TC_ACT_OK	0
#define TC_ACT_SHOT	2

int dump_csum(struct __sk_buff *skb) {
    struct iphdr *ip;
    struct udphdr *udp;
    int l3_len = sizeof(*ip);
    int l4_len = sizeof(*udp);
    int l3_off = 0;
    void *data_end;
    void *data;
    bpf_skb_pull_data(skb, l3_off + l3_len + l4_len);
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    if (data + l3_off + l3_len + l4_len > data_end)
	    return TC_ACT_OK;
    ip = data + l3_off;
    udp = data + l3_off + l3_len;
    bpf_printk("ip check: %x\n", ip->check);
    bpf_printk("udp check: %x\n", udp->check);
    return TC_ACT_OK;
}

SEC("egress")
int _egress(struct __sk_buff *skb) {
    struct iphdr *ip;
    struct udphdr *udp;
    int l3_len = sizeof(*ip);
    int l4_len = sizeof(*udp);
    int l3_off = 0;
    void *data_end;
    void *data;
    __be32 sum;
    int ret = 0;

    bpf_skb_pull_data(skb, l3_off + l3_len + l4_len);
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    if (data + l3_off + l3_len + l4_len > data_end)
	    return TC_ACT_OK;

    ip = data + l3_off;
    udp = data + l3_off + l3_len;

    if (ip->protocol != IPPROTO_UDP)
	    return TC_ACT_OK;

    if ((ip->daddr & 0x00ffffff) != 0x0001ca64) { /* 100.202.1.0/24 */
	    bpf_printk("Different subnet\n");
	    return TC_ACT_OK;
    }

    if (ip->saddr != 0x0201ca64) /* 100.202.1.2 */
	    return TC_ACT_OK;

    __u32 new_daddr = 0x0101ca64; /* 100.202.1.1 */
    if (ip->daddr == 0x0301ca64) { /* 100.202.1.3 */
	sum = bpf_csum_diff(&ip->daddr, 4, &new_daddr, 4, 0);

	ret = bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &new_daddr, 4, 0);
	if (ret < 0)
	  return TC_ACT_SHOT;

	if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
	  return TC_ACT_SHOT;

	return TC_ACT_OK;
    }
    // Remember to change the saddr.
    if (ip->daddr == 0x0401ca64) { /* 100.202.1.4 */
      bpf_printk("ip check: %x\n", ip->check);
      bpf_printk("udp check: %x\n", udp->check);
	if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), ip->daddr, new_daddr, 4) < 0) {
	  return TC_ACT_SHOT;
	}

	if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &new_daddr, 4, 0) < 0) {
	  return TC_ACT_SHOT;
	}
	if (dump_csum(skb) < 0)
	  return TC_ACT_SHOT;

	return TC_ACT_OK;
    }
    if (ip->daddr == 0x0501ca64) { /* 100.202.1.5 */
      bpf_printk("ip check: %x\n", ip->check);
      bpf_printk("udp check: %x\n", udp->check);
	if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &new_daddr, 4, BPF_F_RECOMPUTE_CSUM) < 0)
	  return TC_ACT_SHOT;

	if (dump_csum(skb) < 0)
	  return TC_ACT_SHOT;
	  
	return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

/* NOTE: ingress is complete and it does not need any changes */
SEC("ingress")
int _ingress(struct __sk_buff *skb) {
    struct iphdr *ip;
    int l3_len = sizeof(*ip);
    int l3_off = 0; /* wg0 is L3 device */
    void *data_end;
    void *data;
    __be32 sum;
    int ret = 0;

    bpf_skb_pull_data(skb, l3_off + l3_len);
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    if (data + l3_off + l3_len > data_end)
	    return TC_ACT_OK;

    ip = data + l3_off;

    if (ip->protocol != IPPROTO_UDP)
	    return TC_ACT_OK;

    if (ip->daddr != 0x0201ca64) /* 100.202.1.2 */
	    return TC_ACT_OK;

    if (ip->saddr != 0x0101ca64) /* 100.202.1.1 */
	    return TC_ACT_OK;

    __u32 new_saddr = 0x0401ca64; /* 100.202.1.X - edit this. */
    sum = bpf_csum_diff(&ip->saddr, 4, &new_saddr, 4, 0);

    ret = bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_saddr, 4, 0);
    if (ret < 0)
           return TC_ACT_SHOT;

    if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
           return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
