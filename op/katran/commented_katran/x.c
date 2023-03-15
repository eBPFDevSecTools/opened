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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_seg6local",
    "sk_skb",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "perf_event",
    "cgroup_sysctl",
    "xdp",
    "sched_cls",
    "cgroup_sock_addr",
    "socket_filter",
    "cgroup_skb",
    "kprobe",
    "lwt_out",
    "tracepoint",
    "lwt_in",
    "cgroup_device",
    "sched_act",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "sock_ops",
    "sk_reuseport"
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
