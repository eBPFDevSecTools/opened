// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include "lib/common.h"

#define TO_STRING(X) #X
#define STRINGIFY(X) TO_STRING(X)

/* Use the macros below to set the name of the program and the name of the file
 * containing the implementation for custom_prog(). The values for these macros
 * should typically be passed to the Makefile, for example:
 *
 *     BPF_CUSTOM_PROG_FILE=bytecount.h make
 */

#ifndef BPF_CUSTOM_PROG_FILE
/* Default to bytecount.h for the included file */
#define BPF_CUSTOM_PROG_FILE bytecount.h
#endif

#ifndef BPF_CUSTOM_PROG_NAME
/* Default to __section("custom") for the program */
#define BPF_CUSTOM_PROG_NAME custom
#endif

#include STRINGIFY(BPF_CUSTOM_PROG_FILE)

__section(STRINGIFY(BPF_CUSTOM_PROG_NAME))
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 32,
  "endLine": 45,
  "File": "/home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c",
  "funcName": "custom_hook",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "int custom_hook (const struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 custom_meta = ctx_load_meta (ctx, CB_CUSTOM_CALLS);\n",
    "    __u32 identity = custom_meta & 0xffffff;\n",
    "    int ret = (custom_meta >> 24) & 0xff;\n",
    "    custom_prog (ctx, identity);\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
int custom_hook(const struct __ctx_buff *ctx)
{
	__u32 custom_meta = ctx_load_meta(ctx, CB_CUSTOM_CALLS);
	__u32 identity = custom_meta & 0xffffff;
	int ret = (custom_meta >> 24) & 0xff;

	/* Call user-defined function from custom header file. */
	custom_prog(ctx, identity);

	/* Return action code selected from parent program, independently of
	 * what the custom function does, to maintain datapath consistency.
	 */
	return ret;
}