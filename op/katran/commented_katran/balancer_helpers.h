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
    "bpf_perf_event_output",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "lwt_in",
    "sched_act",
    "xdp",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_skb",
    "socket_filter",
    "sched_cls",
    "perf_event",
    "cgroup_skb",
    "lwt_xmit",
    "tracepoint",
    "sock_ops",
    "lwt_seg6local"
  ],
  "source": [
    "static inline void submit_event (struct xdp_md *ctx, void *map, __u32 event_id, void *data, __u32 size, bool metadata_only)\n",
    "{\n",
    "    struct ctl_value *gk;\n",
    "    __u32 introspection_gk_pos = 5;\n",
    "    gk = bpf_map_lookup_elem (& ctl_array, & introspection_gk_pos);\n",
    "    if (!gk || gk->value == 0) {\n",
    "        return;\n",
    "    }\n",
    "    struct event_metadata md = {}\n",
    "    ;\n",
    "    __u64 flags = BPF_F_CURRENT_CPU;\n",
    "    md.event = event_id;\n",
    "    md.pkt_size = size;\n",
    "    if (metadata_only) {\n",
    "        md.data_len = 0;\n",
    "    }\n",
    "    else {\n",
    "        md.data_len = min_helper (size, MAX_EVENT_SIZE);\n",
    "        flags |= (__u64) md.data_len << 32;\n",
    "    }\n",
    "    bpf_perf_event_output (ctx, map, flags, &md, sizeof (struct event_metadata));\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
    "sched_act",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "flow_dissector",
    "tracepoint",
    "kprobe",
    "lwt_in",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "sk_msg",
    "lwt_seg6local",
    "sk_reuseport",
    "cgroup_sock_addr",
    "lwt_xmit",
    "xdp",
    "raw_tracepoint",
    "sched_cls",
    "perf_event",
    "sock_ops"
  ],
  "source": [
    "static inline int recirculate (struct xdp_md *ctx)\n",
    "{\n",
    "    int i = RECIRCULATION_INDEX;\n",
    "    bpf_tail_call (ctx, &subprograms, i);\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
    "sched_act",
    "cgroup_sysctl",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "kprobe",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "sk_msg",
    "lwt_seg6local",
    "sk_reuseport",
    "cgroup_device",
    "cgroup_sock_addr",
    "lwt_xmit",
    "xdp",
    "raw_tracepoint",
    "sched_cls",
    "perf_event",
    "sock_ops"
  ],
  "source": [
    "static inline int decrement_ttl (void *data, void *data_end, int offset, bool is_ipv6)\n",
    "{\n",
    "    struct iphdr *iph;\n",
    "    struct ipv6hdr *ip6h;\n",
    "    if (is_ipv6) {\n",
    "        if ((data + offset + sizeof (struct ipv6hdr)) > data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        ip6h = (struct ipv6hdr *) (data + offset);\n",
    "        if (!--ip6h->hop_limit) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if ((data + offset + sizeof (struct iphdr)) > data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        iph = (struct iphdr *) (data + offset);\n",
    "        __u32 csum;\n",
    "        if (!--iph->ttl) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        csum = iph->check + 0x0001;\n",
    "        iph->check = (csum & 0xffff) + (csum >> 16);\n",
    "    }\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
