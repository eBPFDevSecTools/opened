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
  "startLine": 30,
  "endLine": 37,
  "File": "/home/sayandes/opened_extraction/examples/katran/xdp_root.c",
  "funcName": "xdp_root",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 15,
      "text": "/* Copyright (C) 2018-present, Facebook, Inc.\n *\n * This program is free software; you can redistribute it and/or modify\n * it under the terms of the GNU General Public License as published by\n * the Free Software Foundation; version 2 of the License.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License along\n * with this program; if not, write to the Free Software Foundation, Inc.,\n * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "XDP_PASS",
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "called_function_list": [
    "unroll"
  ],
  "call_depth": -1,
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
  "startLine": 40,
  "endLine": 47,
  "File": "/home/sayandes/opened_extraction/examples/katran/xdp_root.c",
  "funcName": "xdp_val",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "XDP_PASS",
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "called_function_list": [
    "unroll"
  ],
  "call_depth": -1,
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
