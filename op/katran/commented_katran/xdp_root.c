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
  "capability": [
    {
      "pkt_go_to_next_module": [
        {
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP."
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_tail_call": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"    ctx\",\n  \" &root_array\",\n  \" i\"\n ]\n}"
    ]
  },
  "startLine": 30,
  "endLine": 37,
  "File": "/home/sayandes/opened_extraction/examples/katran/xdp_root.c",
  "Funcname": "xdp_root",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "struct xdp_md *ctx"
  ],
  "Output": "\\xdp\\)",
  "Helper": "bpf_tail_call,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
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
  "capability": [
    {
      "pkt_go_to_next_module": [
        {
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP."
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_tail_call": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"    ctx\",\n  \" &root_array\",\n  \" i\"\n ]\n}"
    ]
  },
  "startLine": 40,
  "endLine": 47,
  "File": "/home/sayandes/opened_extraction/examples/katran/xdp_root.c",
  "Funcname": "xdp_val",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "struct xdp_md *ctx"
  ],
  "Output": "\\xdp\\)",
  "Helper": "bpf_tail_call,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
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
