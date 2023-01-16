/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CSUM_H_
#define __BPF_CSUM_H_

#include "compiler.h"
#include "helpers.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
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
    "All_hookpoints"
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
static __always_inline __sum16 csum_fold(__wsum csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__sum16)~csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
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
    "All_hookpoints"
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
static __always_inline __wsum csum_unfold(__sum16 csum)
{
	return (__wsum)csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
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
    "All_hookpoints"
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
static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	csum += addend;
	return csum + (csum < addend);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
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
    "All_hookpoints"
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
static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "csum_diff": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\treturn _externalfrom",
          " size_from",
          " to",
          " size_to",
          " seed"
        ]
      }
    ]
  },
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
    "lwt_xmit",
    "xdp",
    "sched_cls",
    "lwt_in",
    "lwt_seg6local",
    "lwt_out",
    "sched_act"
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
