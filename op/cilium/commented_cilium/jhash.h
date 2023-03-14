/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2006 Bob Jenkins <bob_jenkins@burtleburtle.net> */
/* Copyright (C) 2006-2020 Authors of the Linux kernel */
/* Copyright Authors of Cilium */

#ifndef __JHASH_H_
#define __JHASH_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define JHASH_INITVAL	0xdeadbeef

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 17,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "rol32",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 word",
    " __u32 shift"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 rol32 (__u32 word, __u32 shift)\n",
    "{\n",
    "    return (word << shift) | (word >> ((-shift) & 31));\n",
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
static __always_inline __u32 rol32(__u32 word, __u32 shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 40,
  "endLine": 81,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "jhash",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *key",
    " __u32 length",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 jhash (const void *key, __u32 length, __u32 initval)\n",
    "{\n",
    "    const unsigned char *k = key;\n",
    "    __u32 a, b, c;\n",
    "    if (!__builtin_constant_p (length))\n",
    "        __throw_build_bug ();\n",
    "    a = b = c = JHASH_INITVAL + length + initval;\n",
    "    while (length > 12) {\n",
    "        a += *(__u32*) (k);\n",
    "        b += *(__u32*) (k + 4);\n",
    "        c += *(__u32*) (k + 8);\n",
    "        __jhash_mix (a, b, c);\n",
    "        length -= 12;\n",
    "        k += 12;\n",
    "    }\n",
    "    switch (length) {\n",
    "    case 12 :\n",
    "        c += (__u32) k[11] << 24;\n",
    "    case 11 :\n",
    "        c += (__u32) k[10] << 16;\n",
    "    case 10 :\n",
    "        c += (__u32) k[9] << 8;\n",
    "    case 9 :\n",
    "        c += (__u32) k[8];\n",
    "    case 8 :\n",
    "        b += (__u32) k[7] << 24;\n",
    "    case 7 :\n",
    "        b += (__u32) k[6] << 16;\n",
    "    case 6 :\n",
    "        b += (__u32) k[5] << 8;\n",
    "    case 5 :\n",
    "        b += (__u32) k[4];\n",
    "    case 4 :\n",
    "        a += (__u32) k[3] << 24;\n",
    "    case 3 :\n",
    "        a += (__u32) k[2] << 16;\n",
    "    case 2 :\n",
    "        a += (__u32) k[1] << 8;\n",
    "    case 1 :\n",
    "        a += (__u32) k[0];\n",
    "        __jhash_final (a, b, c);\n",
    "    case 0 :\n",
    "        break;\n",
    "    }\n",
    "    return c;\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_constant_p",
    "__jhash_mix",
    "__throw_build_bug",
    "__jhash_final"
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
static __always_inline __u32 jhash(const void *key, __u32 length,
				   __u32 initval)
{
	const unsigned char *k = key;
	__u32 a, b, c;

	if (!__builtin_constant_p(length))
		__throw_build_bug();

	a = b = c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += *(__u32 *)(k);
		b += *(__u32 *)(k + 4);
		c += *(__u32 *)(k + 8);

		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}

	switch (length) {
	case 12: c += (__u32)k[11] << 24;
	case 11: c += (__u32)k[10] << 16;
	case 10: c +=  (__u32)k[9] <<  8;
	case 9:  c +=  (__u32)k[8];
	case 8:  b +=  (__u32)k[7] << 24;
	case 7:  b +=  (__u32)k[6] << 16;
	case 6:  b +=  (__u32)k[5] <<  8;
	case 5:  b +=  (__u32)k[4];
	case 4:  a +=  (__u32)k[3] << 24;
	case 3:  a +=  (__u32)k[2] << 16;
	case 2:  a +=  (__u32)k[1] <<  8;
	case 1:  a +=  (__u32)k[0];

		__jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 91,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "__jhash_nwords",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 a",
    " __u32 b",
    " __u32 c",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 __jhash_nwords (__u32 a, __u32 b, __u32 c, __u32 initval)\n",
    "{\n",
    "    a += initval;\n",
    "    b += initval;\n",
    "    c += initval;\n",
    "    __jhash_final (a, b, c);\n",
    "    return c;\n",
    "}\n"
  ],
  "called_function_list": [
    "__jhash_final"
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
static __always_inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c,
					    __u32 initval)
{
	a += initval;
	b += initval;
	c += initval;
	__jhash_final(a, b, c);
	return c;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 93,
  "endLine": 97,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "jhash_3words",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 a",
    " __u32 b",
    " __u32 c",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 jhash_3words (__u32 a, __u32 b, __u32 c, __u32 initval)\n",
    "{\n",
    "    return __jhash_nwords (a, b, c, initval + JHASH_INITVAL + (3 << 2));\n",
    "}\n"
  ],
  "called_function_list": [
    "__jhash_nwords"
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
static __always_inline __u32 jhash_3words(__u32 a, __u32 b, __u32 c,
					  __u32 initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 99,
  "endLine": 102,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "jhash_2words",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 a",
    " __u32 b",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 jhash_2words (__u32 a, __u32 b, __u32 initval)\n",
    "{\n",
    "    return __jhash_nwords (a, b, 0, initval + JHASH_INITVAL + (2 << 2));\n",
    "}\n"
  ],
  "called_function_list": [
    "__jhash_nwords"
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
static __always_inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval)
{
	return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 104,
  "endLine": 107,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/jhash.h",
  "funcName": "jhash_1word",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 a",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 jhash_1word (__u32 a, __u32 initval)\n",
    "{\n",
    "    return __jhash_nwords (a, 0, 0, initval + JHASH_INITVAL + (1 << 2));\n",
    "}\n"
  ],
  "called_function_list": [
    "__jhash_nwords"
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
static __always_inline __u32 jhash_1word(__u32 a, __u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* __JHASH_H_ */
