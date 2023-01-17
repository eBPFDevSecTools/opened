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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/jhash.h",
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
static __always_inline __u32 jhash_1word(__u32 a, __u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif /* __JHASH_H_ */
