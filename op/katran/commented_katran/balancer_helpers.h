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
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 70,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "submit_event",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 15,
      "text": "/* Copyright (C) 2018-present, Facebook, Inc.\n *\n * This program is free software; you can redistribute it and/or modify\n * it under the terms of the GNU General Public License as published by\n * the Free Software Foundation; version 2 of the License.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License along\n * with this program; if not, write to the Free Software Foundation, Inc.,\n * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n */"
    },
    {
      "start_line": 19,
      "end_line": 21,
      "text": "/*\n * This file contains common used routines. such as csum helpers etc\n */"
    },
    {
      "start_line": 43,
      "end_line": 45,
      "text": "/**\n * helper to print blob of data into perf pipe\n */"
    }
  ],
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
    "sock_ops",
    "lwt_out",
    "sched_act",
    "raw_tracepoint_writable",
    "perf_event",
    "raw_tracepoint",
    "lwt_in",
    "kprobe",
    "cgroup_skb",
    "sk_skb",
    "sched_cls",
    "tracepoint",
    "lwt_seg6local",
    "xdp",
    "socket_filter",
    "lwt_xmit"
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
  "called_function_list": [
    "min_helper"
  ],
  "call_depth": -1,
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
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 74,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "recirculate",
  "developer_inline_comments": [
    {
      "start_line": 7,
      "end_line": 7,
      "text": "// we should never hit this"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_PASS",
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int recirculate (struct xdp_md *ctx)\n",
    "{\n",
    "    int i = RECIRCULATION_INDEX;\n",
    "    bpf_tail_call (ctx, &subprograms, i);\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 111,
  "File": "/home/sayandes/opened_extraction/examples/katran/balancer_helpers.h",
  "funcName": "decrement_ttl",
  "developer_inline_comments": [
    {
      "start_line": 13,
      "end_line": 13,
      "text": "// ttl 0"
    },
    {
      "start_line": 23,
      "end_line": 23,
      "text": "// ttl 0"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " int offset",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "called_function_list": [],
  "call_depth": 0,
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
