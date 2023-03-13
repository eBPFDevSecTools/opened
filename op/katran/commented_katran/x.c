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
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sched_act",
    "raw_tracepoint",
    "lwt_xmit",
    "cgroup_sock",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint_writable",
    "xdp",
    "sched_cls",
    "lwt_seg6local",
    "sk_reuseport",
    "sk_skb",
    "socket_filter",
    "kprobe",
    "cgroup_sysctl",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int xdp_prog_simple (struct xdp_md *ctx)\n",
    "{\n",
    "    return xdpdecap (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "xdpdecap"
  ],
  "call_depth": -1,
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
