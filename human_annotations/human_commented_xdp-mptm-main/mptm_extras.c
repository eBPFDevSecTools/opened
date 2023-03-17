/* SPDX-License-Identifier: GPL-2.0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <kernel/lib/mptm-debug.h>

#define MAX_ENTRIES 1024

struct bpf_map_def SEC("maps") mptm_extras_redirect_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES,
};

SEC("mptm_redirect_xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "    return _map&mptm_extras_redirect_devmap",
          " key",
          " flags"
        ]
      }
    ]
  },
  "startLine": 24,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm_extras.c",
  "funcName": "mptm_redirect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_redirect",
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "This function takes in a packet represented by struct xdp_md context and redirects it to another interface via a BPF_REDIRECT_DEVMAP with key which is the packet's ingress interface and flags as zero.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
    },
    {}
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
int mptm_redirect(struct xdp_md *ctx) {
    __u64 flags = 0;
    __u32 key = ctx->ingress_ifindex;

    return bpf_redirect_map(&mptm_extras_redirect_devmap, key, flags);
}

SEC("mptm_pass_xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 32,
  "endLine": 34,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm_extras.c",
  "funcName": "mptm_pass",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sock_ops",
    "lwt_out",
    "raw_tracepoint_writable",
    "kprobe",
    "cgroup_skb",
    "sched_cls",
    "sched_act",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_device",
    "perf_event",
    "cgroup_sock_addr",
    "sk_skb",
    "sk_msg",
    "cgroup_sock",
    "tracepoint",
    "lwt_xmit",
    "socket_filter",
    "lwt_in",
    "xdp"
  ],
  "humanFuncDescription": [
    {
      "description": "This function just returns XDP_PASS for any packet that is passed to it as struct xdp_mp context",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
    },
    {}
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
int mptm_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

