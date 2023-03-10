/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_ACCESS_H_
#define __BPF_ACCESS_H_

#include "compiler.h"

#if !defined(__non_bpf_context) && defined(__bpf__)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 10,
  "endLine": 33,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/access.h",
  "funcName": "map_array_get_32",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *array",
    " __u32 index",
    " const __u32 limit"
  ],
  "output": "static__always_inline__maybe_unused__u32",
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
    "static __always_inline __maybe_unused __u32 map_array_get_32 (const __u32 *array, __u32 index, const __u32 limit)\n",
    "{\n",
    "    __u32 datum = 0;\n",
    "    if (__builtin_constant_p (index) || !__builtin_constant_p (limit))\n",
    "        __throw_build_bug ();\n",
    "    asm volatile (\"%[index] <<= 2\\n\\t\"\n",
    "        \"if %[index] > %[limit] goto +1\\n\\t\"\n",
    "        \"%[array] += %[index]\\n\\t\"\n",
    "        \"%[datum] = *(u32 *)(%[array] + 0)\\n\\t\"\n",
    "        : [datum] \"=r\"\n",
    "        (datum) : [limit] \"i\"\n",
    "        (limit), [array] \"r\"\n",
    "        (array), [index] \"r\"\n",
    "        (index) :);\n",
    "    return datum;\n",
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
static __always_inline __maybe_unused __u32
map_array_get_32(const __u32 *array, __u32 index, const __u32 limit)
{
	__u32 datum = 0;

	if (__builtin_constant_p(index) ||
	    !__builtin_constant_p(limit))
		__throw_build_bug();

	/* LLVM tends to optimize code away that is needed for the verifier to
	 * understand dynamic map access. Input constraint is that index < limit
	 * for this util function, so we never fail here, and returned datum is
	 * always valid.
	 */
	asm volatile("%[index] <<= 2\n\t"
		     "if %[index] > %[limit] goto +1\n\t"
		     "%[array] += %[index]\n\t"
		     "%[datum] = *(u32 *)(%[array] + 0)\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit), [array]"r"(array), [index]"r"(index)
		     : /* no clobbers */ );

	return datum;
}
#else
# define map_array_get_32(array, index, limit)	__throw_build_bug()
#endif /* !__non_bpf_context && __bpf__ */
#endif /* __BPF_ACCESS_H_ */
