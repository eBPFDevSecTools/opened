/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CSUM_H_
#define __BPF_CSUM_H_

#include "compiler.h"
#include "helpers.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 10,
  "endLine": 15,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/csum.h",
  "funcName": "csum_fold",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__wsum csum"
  ],
  "output": "static__always_inline__sum16",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __sum16 csum_fold (__wsum csum)\n",
    "{\n",
    "    csum = (csum & 0xffff) + (csum >> 16);\n",
    "    csum = (csum & 0xffff) + (csum >> 16);\n",
    "    return (__sum16) ~csum;\n",
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
static __always_inline __sum16 csum_fold(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 17,
  "endLine": 20,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/csum.h",
  "funcName": "csum_unfold",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__sum16 csum"
  ],
  "output": "static__always_inline__wsum",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __wsum csum_unfold (__sum16 csum)\n",
    "{\n",
    "    return (__wsum) csum;\n",
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
static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 26,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/csum.h",
  "funcName": "csum_add",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__wsum csum",
    " __wsum addend"
  ],
  "output": "static__always_inline__wsum",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __wsum csum_add (__wsum csum, __wsum addend)\n",
    "{\n",
    "    csum += addend;\n",
    "    return csum + (csum < addend);\n",
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
static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 28,
  "endLine": 31,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/csum.h",
  "funcName": "csum_sub",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__wsum csum",
    " __wsum addend"
  ],
  "output": "static__always_inline__wsum",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "sk_msg",
    "sk_skb",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "cgroup_skb"
  ],
  "source": [
    "static __always_inline __wsum csum_sub (__wsum csum, __wsum addend)\n",
    "{\n",
    "    return csum_add (csum, ~addend);\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_add"
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
static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 33,
  "endLine": 52,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/csum.h",
  "funcName": "csum_diff",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *from",
    " __u32 size_from",
    " const void *to",
    " __u32 size_to",
    " __u32 seed"
  ],
  "output": "static__always_inline__wsum",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "sched_cls",
    "lwt_xmit",
    "lwt_out"
  ],
  "source": [
    "static __always_inline __wsum csum_diff (const void *from, __u32 size_from, const void *to, __u32 size_to, __u32 seed)\n",
    "{\n",
    "    if (__builtin_constant_p (size_from) && __builtin_constant_p (size_to)) {\n",
    "        if (size_from == 4 && size_to == 4 && __builtin_constant_p (seed) && seed == 0)\n",
    "            return csum_add (~(*(__u32*) from), *(__u32*) to);\n",
    "        if (size_from == 4 && size_to == 4)\n",
    "            return csum_add (seed, csum_add (~(*(__u32*) from), *(__u32*) to));\n",
    "    }\n",
    "    return csum_diff_external (from, size_from, to, size_to, seed);\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_constant_p",
    "csum_add",
    "csum_diff_external"
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
static __always_inline __wsum csum_diff(const void *from, __u32 size_from,
					const void *to,   __u32 size_to,
					__u32 seed)
{
	if (__builtin_constant_p(size_from) &&
	    __builtin_constant_p(size_to)) {
		/* Optimizations for frequent hot-path cases that are tiny to just
		 * inline into the code instead of calling more expensive helper.
		 */
		if (size_from == 4 && size_to == 4 &&
		    __builtin_constant_p(seed) && seed == 0)
			return csum_add(~(*(__u32 *)from), *(__u32 *)to);
		if (size_from == 4 && size_to == 4)
			return csum_add(seed,
					csum_add(~(*(__u32 *)from),
						 *(__u32 *)to));
	}

	return csum_diff_external(from, size_from, to, size_to, seed);
}

#endif /* __BPF_CSUM_H_ */
