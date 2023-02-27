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
  "capabilities": [],
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
  "File": "/home/palani/github/opened_extraction/examples/katran/xdp_root.c",
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
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "int SEC (\"xdp\") xdp_root (struct xdp_md *ctx)\n",
    "{\n",
    "    __u32 *fd;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i < ROOT_ARRAY_SIZE; i++) {\n",
    "        bpf_tail_call (ctx, &root_array, i);\n",
    "    }\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Input (struct xdp_md* ctx) is user accessible metadata for XDP packet hook                   The program will jump into another eBPF program.                   For each index in root_array, the program attempts to jump into a program referenced at index i                   and passes ctx, a pointer to the context.                   This programs chains and executes the input program, and finally pass the packet. ",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-24"
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
  "capabilities": [],
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
  "File": "/home/palani/github/opened_extraction/examples/katran/xdp_root.c",
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
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "int SEC (\"xdp\") xdp_val (struct xdp_md *ctx)\n",
    "{\n",
    "    __u32 *fd;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i < ROOT_ARRAY_SIZE; i++) {\n",
    "        bpf_tail_call (ctx, &root_array, i);\n",
    "    }\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Input (struct xdp_md* ctx) is user accessible metadata for XDP packet hook                   The program will jump into another eBPF program.                   For each index in root_array, the program attempts to jump into a program referenced at index i                   and passes ctx, a pointer to the context.                   This programs chains and executes the input program, and finally pass the packet. ",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-24"
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
