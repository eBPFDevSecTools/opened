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
  "File": "/home/sayandes/opened_extraction/examples/katran/x.c",
  "funcName": "xdp_prog_simple",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "xdp",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_in",
    "sock_ops",
    "cgroup_device",
    "flow_dissector",
    "sched_cls",
    "cgroup_sock_addr",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "perf_event",
    "sk_msg",
    "sk_reuseport",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Same as decap_kern, it decaps the packet and pass it to the tcp/ip stack.",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
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
