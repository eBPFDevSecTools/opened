/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_VERIFIER__
#define __BPF_VERIFIER__

#include "compiler.h"

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits on older
 * kernels.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "get_smp_processor_id": [
      {
        "opVar": "#ifndef HAVE_LARGE_INSN_LIMIT       volatile int __maybe_unused id ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 13,
  "endLine": 18,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/verifier.h",
  "funcName": "relax_verifier",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "get_smp_processor_id"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "raw_tracepoint_writable",
    "socket_filter",
    "sched_act",
    "sk_reuseport",
    "xdp",
    "sk_msg",
    "lwt_in",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_xmit",
    "kprobe",
    "perf_event",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "tracepoint",
    "raw_tracepoint",
    "sched_cls",
    "lwt_out"
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
static __always_inline void relax_verifier(void)
{
#ifndef HAVE_LARGE_INSN_LIMIT
       volatile int __maybe_unused id = get_smp_processor_id();
#endif
}

#endif /* __BPF_VERIFIER__ */
