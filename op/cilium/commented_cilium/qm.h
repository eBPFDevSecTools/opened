/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __QM_H_
#define __QM_H_

#include <bpf/ctx/ctx.h>

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 22,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/qm.h",
  "funcName": "reset_queue_mapping",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static inline void reset_queue_mapping (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(RESET_QUEUES) && __ctx_is == __ctx_skb\n",
    "    ctx->queue_mapping = 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "defined"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
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
static inline void reset_queue_mapping(struct __ctx_buff *ctx __maybe_unused)
{
#if defined(RESET_QUEUES) && __ctx_is == __ctx_skb
	/* Workaround for GH-18311 where veth driver might have recorded
	 * veth's RX queue mapping instead of leaving it at 0. This can
	 * cause issues on the phys device where all traffic would only
	 * hit a single TX queue (given veth device had a single one and
	 * mapping was left at 1). Reset so that stack picks a fresh queue.
	 * Kernel fix is at 710ad98c363a ("veth: Do not record rx queue
	 * hint in veth_xmit").
	 */
	ctx->queue_mapping = 0;
#endif
}

#endif /* __QM_H_ */
