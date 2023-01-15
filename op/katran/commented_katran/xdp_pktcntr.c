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

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include "bpf.h"
#include "bpf_helpers.h"

#define CTRL_ARRAY_SIZE 2
#define CNTRS_ARRAY_SIZE 512

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, CTRL_ARRAY_SIZE);
} ctl_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, CNTRS_ARRAY_SIZE);
} cntrs_array SEC(".maps");

SEC("xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "map_read": [
        {
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": "Map value associated to key, or NULL if no entry was found.",
          "Return Type": "void",
          "Function Name": "*bpf_map_lookup_elem",
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
        "opVar": "  __u32* flag ",
        "inpVar": [
          " &ctl_array",
          " &ctl_flag_pos"
        ]
      },
      {
        "opVar": "  __u64* cntr_val ",
        "inpVar": [
          " &cntrs_array",
          " &cntr_pos"
        ]
      }
    ]
  },
  "startLine": 46,
  "endLine": 62,
  "File": "/root/examples/katran/xdp_pktcntr.c",
  "funcName": "pktcntr",
  "updateMaps": [],
  "readMaps": [
    " ctl_array",
    " cntrs_array"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "lwt_out",
    "sock_ops",
    "cgroup_device",
    "cgroup_sysctl",
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
int pktcntr(struct xdp_md* ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  __u32 ctl_flag_pos = 0;
  __u32 cntr_pos = 0;
  __u32* flag = bpf_map_lookup_elem(&ctl_array, &ctl_flag_pos);

  if (!flag || (*flag == 0)) {
    return XDP_PASS;
  };

  __u64* cntr_val = bpf_map_lookup_elem(&cntrs_array, &cntr_pos);
  if (cntr_val) {
    *cntr_val += 1;
  };
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
