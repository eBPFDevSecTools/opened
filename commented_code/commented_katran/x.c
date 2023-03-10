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
    "cgroup_skb",
    "sk_reuseport",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_device",
    "sched_act",
    "lwt_out",
    "socket_filter",
    "sk_msg",
    "xdp",
    "flow_dissector",
    "tracepoint",
    "sock_ops",
    "cgroup_sock_addr",
    "lwt_in",
    "cgroup_sysctl",
    "lwt_seg6local",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "sk_skb",
    "kprobe",
    "cgroup_sock"
  ],
  "source": [
    "int xdp_prog_simple (struct xdp_md *ctx)\n",
    "{\n",
    "    return xdpdecap (ctx);\n",
    "}\n"
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
