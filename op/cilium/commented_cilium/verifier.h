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
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "u32",
          "Description": "Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with preemption disabled , which means that the SMP processor id is stable during all the execution of the program. ",
          "Return": " The SMP id of the processor running the program.",
          "Function Name": "get_smp_processor_id",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
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
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls"
  ],
  "source": [
    "static __always_inline void relax_verifier (void)\n",
    "{\n",
    "\n",
    "#ifndef HAVE_LARGE_INSN_LIMIT\n",
    "    volatile int __maybe_unused id = get_smp_processor_id ();\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __always_inline void relax_verifier(void)
{
#ifndef HAVE_LARGE_INSN_LIMIT
       volatile int __maybe_unused id = get_smp_processor_id();
#endif
}

#endif /* __BPF_VERIFIER__ */
