// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet    */
// #include <netinet/in.h>
#define IPPROTO_UDP 17

__u16 target_port = 53;

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
  void *data_end = (void *)(__u64)ctx->data_end;
  void *data = (void *)(__u64)ctx->data;
  struct ethhdr *l2;
  struct iphdr *l3;
  // linux/udp.h
  struct udphdr *l4;

  if (ctx->protocol != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  l2 = data;
  if ((void *)(l2 + 1) > data_end)
    return TC_ACT_OK;

  l3 = (struct iphdr *)(l2 + 1);
  if ((void *)(l3 + 1) > data_end)
    return TC_ACT_OK;

  if (l3->protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  l4 = (struct udphdr *)(l3 + 1);
  if ((void *)(l4 + 1) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(l4->dest) != target_port)
    return TC_ACT_OK;

  bpf_printk("Got DNS packet: dst addr %d.%d.%d.%d port %d",
             ((l3->daddr >> 0) & 0xff),
             ((l3->daddr >> 8) & 0xff),
             ((l3->daddr >> 16) & 0xff),
             ((l3->daddr >> 24) & 0xff),
             bpf_ntohs(l4->dest));

  if (bpf_skb_pull_data(ctx, 0) < 0)
    return TC_ACT_OK;
        
  data = (void *)(l4+1);
  void *cur;
  char payload[33] = {0};
  int j = 0;
  for(int i = 12; i < 12+32;) {
    cur = data + i;
    i += 1;
    if ((void *)(cur) > data_end)
      return TC_ACT_OK;

    char byte;
    bpf_probe_read_kernel(&byte, 1, cur);
    if (byte == 0)
      break;

    if (byte < 'a') {
      payload[j] = '.';
    } else {
      payload[j] = byte;
    }
    j += 1;
  }
  bpf_printk("Payload domain = %s", payload);

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
