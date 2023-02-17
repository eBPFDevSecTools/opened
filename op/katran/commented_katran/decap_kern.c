/* Copyright (C) 2019-present, Facebook, Inc.
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

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdbool.h>
#include <stddef.h>

#include "balancer_consts.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "decap_maps.h"
#include "pckt_encap.h"
#include "pckt_parsing.h"

#ifndef DECAP_PROG_SEC
#define DECAP_PROG_SEC "xdp"
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 34,
  "endLine": 83,
  "File": "/home/sayandes/opened_extraction/examples/katran/decap_kern.c",
  "funcName": "process_l3_headers",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct packet_description *pckt",
    " __u8 *protocol",
    " __u64 off",
    " __u16 *pkt_bytes",
    " void *data",
    " void *data_end",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Process layer 3 headers. Drop the packet if it is 1)bogus packet, len less than minimum ethernet frame size, 2)fragmented, 3)ipv4 header not equals to 20 bytes,",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
    }
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
__attribute__((__always_inline__)) static inline int process_l3_headers(
    struct packet_description* pckt,
    __u8* protocol,
    __u64 off,
    __u16* pkt_bytes,
    void* data,
    void* data_end,
    bool is_ipv6) {
  __u64 iph_len;
  struct iphdr* iph;
  struct ipv6hdr* ip6h;
  if (is_ipv6) {
    ip6h = data + off;
    if (ip6h + 1 > data_end) {
      return XDP_DROP;
    }

    iph_len = sizeof(struct ipv6hdr);
    *protocol = ip6h->nexthdr;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(ip6h->payload_len);
    off += iph_len;
    if (*protocol == IPPROTO_FRAGMENT) {
      // we drop fragmented packets
      return XDP_DROP;
    }
  } else {
    iph = data + off;
    if (iph + 1 > data_end) {
      return XDP_DROP;
    }
    // ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5) {
      // if len of ipv4 hdr is not equal to 20bytes that means that header
      // contains ip options, and we dont support em
      return XDP_DROP;
    }

    *protocol = iph->protocol;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
      // we drop fragmented packets.
      return XDP_DROP;
    }
  }
  return FURTHER_PROCESSING;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 85,
  "endLine": 120,
  "File": "/home/sayandes/opened_extraction/examples/katran/decap_kern.c",
  "funcName": "process_encaped_ipip_pckt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void **data",
    " void **data_end",
    " struct xdp_md *xdp",
    " bool *is_ipv6",
    " struct packet_description *pckt",
    " __u8 *protocol",
    " __u64 off",
    " __u16 *pkt_bytes"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Process layer 3 headers. Drop the packet if it is 1)bogus packet, len less than minimum ethernet frame size, 2)fragmented, 3)ipv4 header not equals to 20 bytes,",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
    }
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
__attribute__((__always_inline__)) static inline int process_encaped_ipip_pckt(
    void** data,
    void** data_end,
    struct xdp_md* xdp,
    bool* is_ipv6,
    struct packet_description* pckt,
    __u8* protocol,
    __u64 off,
    __u16* pkt_bytes) {
  if (*protocol == IPPROTO_IPIP) {
    if (*is_ipv6) {
      if ((*data + sizeof(struct ipv6hdr) + sizeof(struct ethhdr)) >
          *data_end) {
        return XDP_DROP;
      }
      if (!decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    } else {
      if ((*data + sizeof(struct iphdr) + sizeof(struct ethhdr)) > *data_end) {
        return XDP_DROP;
      }
      if (!decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
      }
    }
  } else if (*protocol == IPPROTO_IPV6) {
    if ((*data + sizeof(struct ipv6hdr) + sizeof(struct ethhdr)) > *data_end) {
      return XDP_DROP;
    }
    if (!decap_v6(xdp, data, data_end, false)) {
      return XDP_DROP;
    }
  }
  return FURTHER_PROCESSING;
}

#ifdef INLINE_DECAP_GUE
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 123,
  "endLine": 161,
  "File": "/home/sayandes/opened_extraction/examples/katran/decap_kern.c",
  "funcName": "process_encaped_gue_pckt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void **data",
    " void **data_end",
    " struct xdp_md *xdp",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Process layer 3 headers. Drop the packet if it is 1)bogus packet, len less than minimum ethernet frame size, 2)fragmented, 3)ipv4 header not equals to 20 bytes,",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
    }
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
__attribute__((__always_inline__)) static inline int process_encaped_gue_pckt(
    void** data,
    void** data_end,
    struct xdp_md* xdp,
    bool is_ipv6) {
  int offset = 0;
  if (is_ipv6) {
    __u8 v6 = 0;
    offset =
        sizeof(struct ipv6hdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    // 1 byte for gue v1 marker to figure out what is internal protocol
    if ((*data + offset + 1) > *data_end) {
      return XDP_DROP;
    }
    v6 = ((__u8*)(*data))[offset];
    v6 &= GUEV1_IPV6MASK;
    if (v6) {
      // inner packet is ipv6 as well
      if (!gue_decap_v6(xdp, data, data_end, false)) {
        return XDP_DROP;
      }
    } else {
      // inner packet is ipv4
      if (!gue_decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    }
  } else {
    offset =
        sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    if (!gue_decap_v4(xdp, data, data_end)) {
      return XDP_DROP;
    }
  }
  return FURTHER_PROCESSING;
}
#endif // INLINE_DECAP_GUE

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "  data_stats ",
        "inpVar": [
          " &decap_counters",
          " &key"
        ]
      }
    ]
  },
  "startLine": 164,
  "endLine": 221,
  "File": "/home/sayandes/opened_extraction/examples/katran/decap_kern.c",
  "funcName": "process_packet",
  "updateMaps": [],
  "readMaps": [
    "  decap_counters"
  ],
  "input": [
    "void *data",
    " __u64 off",
    " void *data_end",
    " bool is_ipv6",
    " struct xdp_md *xdp"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Process layer 3 headers. Drop the packet if it is 1)bogus packet, len less than minimum ethernet frame size, 2)fragmented, 3)ipv4 header not equals to 20 bytes,",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
    }
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
__attribute__((__always_inline__)) static inline int process_packet(
    void* data,
    __u64 off,
    void* data_end,
    bool is_ipv6,
    struct xdp_md* xdp) {
  struct packet_description pckt = {};
  struct decap_stats* data_stats;
  __u32 key = 0;
  __u8 protocol;

  int action;
  __u16 pkt_bytes;
  action = process_l3_headers(
      &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6);
  if (action >= 0) {
    return action;
  }
  protocol = pckt.flow.proto;

  data_stats = bpf_map_lookup_elem(&decap_counters, &key);
  if (!data_stats) {
    return XDP_PASS;
  }

  data_stats->total += 1;
  if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
    if (is_ipv6) {
      data_stats->decap_v6 += 1;
    } else {
      data_stats->decap_v4 += 1;
    }
    action = process_encaped_ipip_pckt(
        &data, &data_end, xdp, &is_ipv6, &pckt, &protocol, off, &pkt_bytes);
    if (action >= 0) {
      return action;
    }
  }
#ifdef INLINE_DECAP_GUE
  else if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
      return XDP_PASS;
    }
    if (pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) {
      if (is_ipv6) {
        data_stats->decap_v6 += 1;
      } else {
        data_stats->decap_v4 += 1;
      }
      action = process_encaped_gue_pckt(&data, &data_end, xdp, is_ipv6);
      if (action >= 0) {
        return action;
      }
    }
  }
#endif // INLINE_DECAP_GUE
  return XDP_PASS;
}

SEC("decap")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 224,
  "endLine": 247,
  "File": "/home/sayandes/opened_extraction/examples/katran/decap_kern.c",
  "funcName": "xdpdecap",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Process layer 3 headers. Drop the packet if it is 1)bogus packet, len less than minimum ethernet frame size, 2)fragmented, 3)ipv4 header not equals to 20 bytes,",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
    }
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
int xdpdecap(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return XDP_DROP;
  }

  eth_proto = eth->h_proto;

  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(data, nh_off, data_end, false, ctx);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    return process_packet(data, nh_off, data_end, true, ctx);
  } else {
    // pass to tcp/ip stack
    return XDP_PASS;
  }
}

//char _license[] SEC("license") = "GPL";
