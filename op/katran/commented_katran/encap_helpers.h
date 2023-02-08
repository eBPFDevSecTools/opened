/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ENCAP_HELPERS_H
#define __ENCAP_HELPERS_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <string.h>

#include "balancer_consts.h"
#include "bpf.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "csum_helpers.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 55,
  "File": "/home/palani/github/opened_extraction/examples/katran/encap_helpers.h",
  "funcName": "create_v4_hdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr *iph",
    " __u8 tos",
    " __u32 saddr",
    " __u32 daddr",
    " __u16 pkt_bytes",
    " __u8 proto"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "lwt_out",
    "tracepoint",
    "sk_skb",
    "sk_msg",
    "raw_tracepoint_writable",
    "cgroup_device",
    "sched_cls",
    "lwt_in",
    "cgroup_sock",
    "cgroup_skb",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sk_reuseport",
    "sched_act",
    "perf_event",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_xmit",
    "xdp",
    "flow_dissector",
    "lwt_seg6local"
  ],
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline void create_v4_hdr(
    struct iphdr* iph,
    __u8 tos,
    __u32 saddr,
    __u32 daddr,
    __u16 pkt_bytes,
    __u8 proto) {
  __u64 csum = 0;
  iph->version = 4;
  iph->ihl = 5;
  iph->frag_off = 0;
  iph->protocol = proto;
  iph->check = 0;
#ifdef COPY_INNER_PACKET_TOS
  iph->tos = tos;
#else
  iph->tos = DEFAULT_TOS;
#endif
  iph->tot_len = bpf_htons(pkt_bytes + sizeof(struct iphdr));
  iph->daddr = daddr;
  iph->saddr = saddr;
  iph->ttl = DEFAULT_TTL;
  ipv4_csum_inline(iph, &csum);
  iph->check = csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 77,
  "File": "/home/palani/github/opened_extraction/examples/katran/encap_helpers.h",
  "funcName": "create_v6_hdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6hdr *ip6h",
    " __u8 tc",
    " __u32 *saddr",
    " __u32 *daddr",
    " __u16 payload_len",
    " __u8 proto"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "lwt_out",
    "tracepoint",
    "sk_skb",
    "sk_msg",
    "raw_tracepoint_writable",
    "cgroup_device",
    "sched_cls",
    "lwt_in",
    "cgroup_sock",
    "cgroup_skb",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sk_reuseport",
    "sched_act",
    "perf_event",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_xmit",
    "xdp",
    "flow_dissector",
    "lwt_seg6local"
  ],
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline void create_v6_hdr(
    struct ipv6hdr* ip6h,
    __u8 tc,
    __u32* saddr,
    __u32* daddr,
    __u16 payload_len,
    __u8 proto) {
  ip6h->version = 6;
  memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
#ifdef COPY_INNER_PACKET_TOS
  ip6h->priority = (tc & 0xF0) >> 4;
  ip6h->flow_lbl[0] = (tc & 0x0F) << 4;
#else
  ip6h->priority = DEFAULT_TOS;
#endif
  ip6h->nexthdr = proto;
  ip6h->payload_len = bpf_htons(payload_len);
  ip6h->hop_limit = DEFAULT_TTL;
  memcpy(ip6h->saddr.s6_addr32, saddr, 16);
  memcpy(ip6h->daddr.s6_addr32, daddr, 16);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 79,
  "endLine": 89,
  "File": "/home/palani/github/opened_extraction/examples/katran/encap_helpers.h",
  "funcName": "create_udp_hdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct udphdr *udph",
    " __u16 sport",
    " __u16 dport",
    " __u16 len",
    " __u16 csum"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "lwt_out",
    "tracepoint",
    "sk_skb",
    "sk_msg",
    "raw_tracepoint_writable",
    "cgroup_device",
    "sched_cls",
    "lwt_in",
    "cgroup_sock",
    "cgroup_skb",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sk_reuseport",
    "sched_act",
    "perf_event",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_xmit",
    "xdp",
    "flow_dissector",
    "lwt_seg6local"
  ],
  "humanFuncDescription": [
    null
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline void create_udp_hdr(
    struct udphdr* udph,
    __u16 sport,
    __u16 dport,
    __u16 len,
    __u16 csum) {
  udph->source = sport;
  udph->dest = bpf_htons(dport);
  udph->len = bpf_htons(len);
  udph->check = csum;
}

#endif // of __ENCAP_HELPERS_H
