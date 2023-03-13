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
    "sched_cls",
    "cgroup_sock_addr",
    "lwt_out",
    "sock_ops",
    "xdp",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "kprobe",
    "sk_reuseport",
    "tracepoint",
    "lwt_in",
    "sched_act",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sk_msg",
    "perf_event",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "cgroup_sock",
    "cgroup_device",
    "socket_filter"
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
