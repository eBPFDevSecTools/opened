/* Copyright (C) 2018-present, Facebook, Inc.
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

#ifndef __BALANCER_HELPERS
#define __BALANCER_HELPERS
/*
 * This file contains common used routines. such as csum helpers etc
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdbool.h>

#include "balancer_consts.h"
#include "balancer_structs.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "control_data_maps.h"
#include "csum_helpers.h"
#include "introspection.h"

#define bpf_printk(fmt, ...)                                   \
  ({                                                           \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

#ifdef KATRAN_INTROSPECTION
/**
 * helper to print blob of data into perf pipe
 */
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
        "opVar": "  gk ",
        "inpVar": [
          " &ctl_array",
          " &introspection_gk_pos"
        ]
      }
    ],
    "bpf_perf_event_output": [
      {
        "opVar": "NA",
        "inpVar": [
          "    ctx",
          " map",
          " flags",
          " &md",
          " sizeofstruct event_metadata"
        ]
      }
    ]
  },
  "startLine": 46,
  "endLine": 70,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "submit_event",
  "updateMaps": [],
  "readMaps": [
    "  ctl_array"
  ],
  "input": [
    "struct xdp_md *ctx",
    " void *map",
    " __u32 event_id",
    " void *data",
    " __u32 size",
    " bool metadata_only"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "lwt_in",
    "sched_act",
    "socket_filter",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "tracepoint",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "lwt_out",
    "sk_skb",
    "sock_ops",
    "lwt_seg6local",
    "xdp",
    "kprobe"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
__attribute__((__always_inline__)) static inline void submit_event(
    struct xdp_md* ctx,
    void* map,
    __u32 event_id,
    void* data,
    __u32 size,
    bool metadata_only) {
  struct ctl_value* gk;
  __u32 introspection_gk_pos = 5;
  gk = bpf_map_lookup_elem(&ctl_array, &introspection_gk_pos);
  if (!gk || gk->value == 0) {
    return;
  }
  struct event_metadata md = {};
  __u64 flags = BPF_F_CURRENT_CPU;
  md.event = event_id;
  md.pkt_size = size;
  if (metadata_only) {
    md.data_len = 0;
  } else {
    md.data_len = min_helper(size, MAX_EVENT_SIZE);
    flags |= (__u64)md.data_len << 32;
  }
  bpf_perf_event_output(ctx, map, flags, &md, sizeof(struct event_metadata));
}
#endif

#ifdef INLINE_DECAP_GENERIC
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "  ctx",
          " &subprograms",
          " i"
        ]
      }
    ]
  },
  "startLine": 74,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "recirculate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "lwt_in",
    "cgroup_sock_addr",
    "sched_act",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "lwt_seg6local",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "kprobe",
    "socket_filter",
    "lwt_out",
    "sk_msg",
    "xdp",
    "sk_reuseport",
    "sched_cls",
    "tracepoint",
    "sk_skb"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
__attribute__((__always_inline__)) static inline int recirculate(
    struct xdp_md* ctx) {
  int i = RECIRCULATION_INDEX;
  bpf_tail_call(ctx, &subprograms, i);
  // we should never hit this
  return XDP_PASS;
}
#endif // of INLINE_DECAP_GENERIC

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 111,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "decrement_ttl",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " int offset",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_in",
    "cgroup_sock_addr",
    "sched_act",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "lwt_seg6local",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "kprobe",
    "cgroup_device",
    "socket_filter",
    "lwt_out",
    "sk_msg",
    "xdp",
    "sk_reuseport",
    "sched_cls",
    "tracepoint",
    "sk_skb",
    "cgroup_sysctl"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
__attribute__((__always_inline__)) static inline int
decrement_ttl(void* data, void* data_end, int offset, bool is_ipv6) {
  struct iphdr* iph;
  struct ipv6hdr* ip6h;

  if (is_ipv6) {
    if ((data + offset + sizeof(struct ipv6hdr)) > data_end) {
      return XDP_DROP;
    }
    ip6h = (struct ipv6hdr*)(data + offset);
    if (!--ip6h->hop_limit) {
      // ttl 0
      return XDP_DROP;
    }
  } else {
    if ((data + offset + sizeof(struct iphdr)) > data_end) {
      return XDP_DROP;
    }
    iph = (struct iphdr*)(data + offset);
    __u32 csum;
    if (!--iph->ttl) {
      // ttl 0
      return XDP_DROP;
    }
    csum = iph->check + 0x0001;
    iph->check = (csum & 0xffff) + (csum >> 16);
  }
  return FURTHER_PROCESSING;
}

#endif
