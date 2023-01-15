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

#include "bpf.h"
#include "bpf_helpers.h"

#define ROOT_ARRAY_SIZE 3

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, ROOT_ARRAY_SIZE);
} root_array SEC(".maps");


/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "    ctx",
          " &root_array",
          " i"
        ]
      }
    ]
  },
  "startLine": 30,
  "endLine": 37,
  "File": "/root/examples/katran/xdp_root.c",
  "funcName": "xdp_root",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "lwt_out",
    "sock_ops",
    "raw_tracepoint_writable",
    "cgroup_sock_addr",
    "sk_skb",
    "flow_dissector",
    "sched_act",
    "lwt_in",
    "xdp",
    "sk_msg",
    "tracepoint",
    "lwt_seg6local",
    "perf_event",
    "raw_tracepoint",
    "cgroup_skb",
    "kprobe",
    "socket_filter"
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
int SEC("xdp") xdp_root(struct xdp_md* ctx) {
  __u32* fd;
#pragma clang loop unroll(full)
  for (__u32 i = 0; i < ROOT_ARRAY_SIZE; i++) {
    bpf_tail_call(ctx, &root_array, i);
  }
  return XDP_PASS;
}


/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "    ctx",
          " &root_array",
          " i"
        ]
      }
    ]
  },
  "startLine": 40,
  "endLine": 47,
  "File": "/root/examples/katran/xdp_root.c",
  "funcName": "xdp_val",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "lwt_out",
    "sock_ops",
    "raw_tracepoint_writable",
    "cgroup_sock_addr",
    "sk_skb",
    "flow_dissector",
    "sched_act",
    "lwt_in",
    "xdp",
    "sk_msg",
    "tracepoint",
    "lwt_seg6local",
    "perf_event",
    "raw_tracepoint",
    "cgroup_skb",
    "kprobe",
    "socket_filter"
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
int SEC("xdp") xdp_val(struct xdp_md* ctx) {
  __u32* fd;
#pragma clang loop unroll(full)
  for (__u32 i = 0; i < ROOT_ARRAY_SIZE; i++) {
    bpf_tail_call(ctx, &root_array, i);
  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
