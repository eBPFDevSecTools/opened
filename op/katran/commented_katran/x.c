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
    "cgroup_device",
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
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "int xdp_prog_simple (struct xdp_md *ctx)\n",
    "{\n",
    "    return xdpdecap (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Same as decap_kern, it decaps the packet and pass it to the tcp/ip stack. ",
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
int  xdp_prog_simple(struct xdp_md *ctx)
{
  return xdpdecap(ctx);
//return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
