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
  "File": "/home/palani/github/opened_extraction/examples/cilium/include/bpf/access.h",
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
    "sk_msg",
    "lwt_xmit",
    "cgroup_sock_addr",
    "sock_ops",
    "sk_skb",
    "lwt_seg6local",
    "perf_event",
    "cgroup_sysctl",
    "cgroup_sock",
    "xdp",
    "socket_filter",
    "cgroup_skb",
    "kprobe",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "sched_cls",
    "sched_act",
    "raw_tracepoint",
    "flow_dissector",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "tracepoint"
  ],
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
