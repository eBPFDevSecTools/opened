/* SPDX-License-Identifier: GPL-2.0 */

#include "decap_kern.c"

//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>

SEC("xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 13,
  "File": "/home/palani/github/opened_extraction/examples/katran/x.c",
  "funcName": "xdp_prog_simple",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sock_ops",
    "kprobe",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "raw_tracepoint",
    "socket_filter",
    "perf_event",
    "cgroup_sysctl",
    "sched_act",
    "cgroup_sock_addr",
    "sk_msg",
    "sk_reuseport",
    "xdp",
    "lwt_xmit",
    "tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "lwt_seg6local",
    "sk_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "cgroup_sock"
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
int  xdp_prog_simple(struct xdp_md *ctx)
{
  return xdpdecap(ctx);
//return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
