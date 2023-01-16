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
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "u32",
          "Description": "Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with preemption disabled , which means that the SMP processor id is stable during all the execution of the program. ",
          "Return": " The SMP id of the processor running the program.",
          "Function Name": "get_smp_processor_id",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
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
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "lwt_out",
    "cgroup_sock_addr"
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
