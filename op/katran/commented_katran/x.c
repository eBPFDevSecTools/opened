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
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: GPL-2.0 */"
    },
    {
      "start_line": 5,
      "end_line": 5,
      "text": "//#include <linux/bpf.h>"
    },
    {
      "start_line": 6,
      "end_line": 6,
      "text": "//#include <bpf/bpf_helpers.h>"
    },
    {
      "start_line": 12,
      "end_line": 12,
      "text": "//return XDP_PASS;"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "perf_event",
    "lwt_in",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sock",
    "sched_cls",
    "cgroup_sysctl",
    "socket_filter",
    "sk_skb",
    "sock_ops",
    "kprobe",
    "sched_act",
    "flow_dissector",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_out",
    "lwt_xmit",
    "cgroup_skb",
    "cgroup_device",
    "sk_reuseport",
    "xdp"
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
