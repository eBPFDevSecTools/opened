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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/qm.h",
  "funcName": "reset_queue_mapping",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "xdp",
    "lwt_xmit",
    "tracepoint",
    "cgroup_device",
    "lwt_seg6local",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sched_act",
    "flow_dissector",
    "sk_msg",
    "cgroup_sock_addr",
    "lwt_out",
    "cgroup_sock",
    "sk_reuseport",
    "lwt_in",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "sched_cls"
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
