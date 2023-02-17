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
    "sched_act",
    "lwt_xmit",
    "xdp",
    "sched_cls"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
    "lwt_out",
    "lwt_in",
    "raw_tracepoint_writable",
    "sk_skb",
    "flow_dissector",
    "lwt_seg6local",
    "xdp",
    "socket_filter",
    "raw_tracepoint",
    "sched_act",
    "lwt_xmit",
    "sched_cls",
    "cgroup_sysctl",
    "sock_ops",
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "perf_event",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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

