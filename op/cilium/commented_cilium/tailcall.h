/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_TAILCALL_H_
#define __BPF_TAILCALL_H_

#include "compiler.h"

#if !defined(__non_bpf_context) && defined(__bpf__)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "_staticconst struct __ctx_buff *ctx",
          " const void *map",
          "\t\t const __u32 slot"
        ]
      }
    ]
  },
  "startLine": 10,
  "endLine": 33,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/tailcall.h",
  "funcName": "tail_call_static",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx",
    " const void *map",
    " const __u32 slot"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "static __always_inline __maybe_unused void tail_call_static (const struct  __ctx_buff *ctx, const void *map, const __u32 slot)\n",
    "{\n",
    "    if (!__builtin_constant_p (slot))\n",
    "        __throw_build_bug ();\n",
    "    asm volatile (\"r1 = %[ctx]\\n\\t\"\n",
    "        \"r2 = %[map]\\n\\t\"\n",
    "        \"r3 = %[slot]\\n\\t\"\n",
    "        \"call 12\\n\\t\"\n",
    "        : : [ctx] \"r\"\n",
    "        (ctx), [map] \"r\"\n",
    "        (map), [slot] \"i\"\n",
    "        (slot) : \"r0\",\n",
    "        \"r1\",\n",
    "        \"r2\",\n",
    "        \"r3\",\n",
    "        \"r4\",\n",
    "        \"r5\"\n",
    "        );\n",
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
static __always_inline __maybe_unused void
tail_call_static(const struct __ctx_buff *ctx, const void *map,
		 const __u32 slot)
{
	if (!__builtin_constant_p(slot))
		__throw_build_bug();

	/* Don't gamble, but _guarantee_ that LLVM won't optimize setting
	 * r2 and r3 from different paths ending up at the same call insn as
	 * otherwise we won't be able to use the jmpq/nopl retpoline-free
	 * patching by the x86-64 JIT in the kernel.
	 *
	 * Note on clobber list: we need to stay in-line with BPF calling
	 * convention, so even if we don't end up using r0, r4, r5, we need
	 * to mark them as clobber so that LLVM doesn't end up using them
	 * before / after the call.
	 */
	asm volatile("r1 = %[ctx]\n\t"
		     "r2 = %[map]\n\t"
		     "r3 = %[slot]\n\t"
		     "call 12\n\t"
		     :: [ctx]"r"(ctx), [map]"r"(map), [slot]"i"(slot)
		     : "r0", "r1", "r2", "r3", "r4", "r5");
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "_dynamicstruct __ctx_buff *ctx",
          " const void *map",
          " __u32 slot"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tctx",
          " map",
          " slot"
        ]
      }
    ]
  },
  "startLine": 35,
  "endLine": 46,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/tailcall.h",
  "funcName": "tail_call_dynamic",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const void *map",
    " __u32 slot"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "static __always_inline __maybe_unused void tail_call_dynamic (struct  __ctx_buff *ctx, const void *map, __u32 slot)\n",
    "{\n",
    "    if (__builtin_constant_p (slot))\n",
    "        __throw_build_bug ();\n",
    "    tail_call (ctx, map, slot);\n",
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
static __always_inline __maybe_unused void
tail_call_dynamic(struct __ctx_buff *ctx, const void *map, __u32 slot)
{
	if (__builtin_constant_p(slot))
		__throw_build_bug();

	/* Only for the case where slot is not known at compilation time,
	 * we give LLVM a free pass to optimize since we cannot do much
	 * here anyway as x86-64 JIT will emit a retpoline for this case.
	 */
	tail_call(ctx, map, slot);
}
#else
/* BPF unit tests compile some BPF code under their native arch. Tail calls
 * won't work in this context. Only compile above under __bpf__ target.
 */
# define tail_call_static(ctx, map, slot)	__throw_build_bug()
# define tail_call_dynamic(ctx, map, slot)	__throw_build_bug()
#endif /* !__non_bpf_context && __bpf__ */
#endif /* __BPF_TAILCALL_H_ */
