/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef _LINUX_SWAB_H
#define _LINUX_SWAB_H

#include <linux/types.h>

/*
 * casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to __u16, __u32, __u64. At least not in a portable way.
 */
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))

#define ___constant_swab32(x) ((__u32)(				\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab64(x) ((__u64)(				\
	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

#define ___constant_swahw32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x0000ffffUL) << 16) |		\
	(((__u32)(x) & (__u32)0xffff0000UL) >> 16)))

#define ___constant_swahb32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x00ff00ffUL) << 8) |		\
	(((__u32)(x) & (__u32)0xff00ff00UL) >> 8)))

/*
 * Implement the following as inlines, but define the interface using
 * macros to allow constant folding when possible:
 * ___swab16, ___swab32, ___swab64, ___swahw32, ___swahb32
 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 55,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__fswab16",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 val"
  ],
  "output": "static__inline____u16",
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
    "static __inline__ __u16 __fswab16 (__u16 val)\n",
    "{\n",
    "\n",
    "#ifdef __HAVE_BUILTIN_BSWAP16__\n",
    "    return __builtin_bswap16 (val);\n",
    "\n",
    "#elif defined (__arch_swab16)\n",
    "    return __arch_swab16 (val);\n",
    "\n",
    "#else\n",
    "    return ___constant_swab16 (val);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "___constant_swab16",
    "__builtin_bswap16",
    "__arch_swab16",
    "defined"
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
static __inline__  __u16 __fswab16(__u16 val)
{
#ifdef __HAVE_BUILTIN_BSWAP16__
	return __builtin_bswap16(val);
#elif defined (__arch_swab16)
	return __arch_swab16(val);
#else
	return ___constant_swab16(val);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 66,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__fswab32",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 val"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __fswab32 (__u32 val)\n",
    "{\n",
    "\n",
    "#ifdef __HAVE_BUILTIN_BSWAP32__\n",
    "    return __builtin_bswap32 (val);\n",
    "\n",
    "#elif defined(__arch_swab32)\n",
    "    return __arch_swab32 (val);\n",
    "\n",
    "#else\n",
    "    return ___constant_swab32 (val);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swab32",
    "___constant_swab32",
    "__builtin_bswap32",
    "defined"
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
static __inline__  __u32 __fswab32(__u32 val)
{
#ifdef __HAVE_BUILTIN_BSWAP32__
	return __builtin_bswap32(val);
#elif defined(__arch_swab32)
	return __arch_swab32(val);
#else
	return ___constant_swab32(val);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 68,
  "endLine": 81,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__fswab64",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u64 val"
  ],
  "output": "static__inline____u64",
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
    "static __inline__ __u64 __fswab64 (__u64 val)\n",
    "{\n",
    "\n",
    "#ifdef __HAVE_BUILTIN_BSWAP64__\n",
    "    return __builtin_bswap64 (val);\n",
    "\n",
    "#elif defined (__arch_swab64)\n",
    "    return __arch_swab64 (val);\n",
    "\n",
    "#elif defined(__SWAB_64_THRU_32__)\n",
    "    __u32 h = val >> 32;\n",
    "    __u32 l = val & ((1ULL << 32) - 1);\n",
    "    return (((__u64) __fswab32 (l)) << 32) | ((__u64) (__fswab32 (h)));\n",
    "\n",
    "#else\n",
    "    return ___constant_swab64 (val);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swab64",
    "__builtin_bswap64",
    "___constant_swab64",
    "__fswab32",
    "defined"
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
static __inline__  __u64 __fswab64(__u64 val)
{
#ifdef __HAVE_BUILTIN_BSWAP64__
	return __builtin_bswap64(val);
#elif defined (__arch_swab64)
	return __arch_swab64(val);
#elif defined(__SWAB_64_THRU_32__)
	__u32 h = val >> 32;
	__u32 l = val & ((1ULL << 32) - 1);
	return (((__u64)__fswab32(l)) << 32) | ((__u64)(__fswab32(h)));
#else
	return ___constant_swab64(val);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__fswahw32",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 val"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __fswahw32 (__u32 val)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahw32\n",
    "    return __arch_swahw32 (val);\n",
    "\n",
    "#else\n",
    "    return ___constant_swahw32 (val);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "___constant_swahw32",
    "__arch_swahw32"
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
static __inline__  __u32 __fswahw32(__u32 val)
{
#ifdef __arch_swahw32
	return __arch_swahw32(val);
#else
	return ___constant_swahw32(val);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 92,
  "endLine": 99,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__fswahb32",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 val"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __fswahb32 (__u32 val)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahb32\n",
    "    return __arch_swahb32 (val);\n",
    "\n",
    "#else\n",
    "    return ___constant_swahb32 (val);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "___constant_swahb32",
    "__arch_swahb32"
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
static __inline__  __u32 __fswahb32(__u32 val)
{
#ifdef __arch_swahb32
	return __arch_swahb32(val);
#else
	return ___constant_swahb32(val);
#endif
}

/**
 * __swab16 - return a byteswapped 16-bit value
 * @x: value to byteswap
 */
#define __swab16(x)				\
	(__builtin_constant_p((__u16)(x)) ?	\
	___constant_swab16(x) :			\
	__fswab16(x))

/**
 * __swab32 - return a byteswapped 32-bit value
 * @x: value to byteswap
 */
#define __swab32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swab32(x) :			\
	__fswab32(x))

/**
 * __swab64 - return a byteswapped 64-bit value
 * @x: value to byteswap
 */
#define __swab64(x)				\
	(__builtin_constant_p((__u64)(x)) ?	\
	___constant_swab64(x) :			\
	__fswab64(x))

/**
 * __swahw32 - return a word-swapped 32-bit value
 * @x: value to wordswap
 *
 * __swahw32(0x12340000) is 0x00001234
 */
#define __swahw32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahw32(x) :		\
	__fswahw32(x))

/**
 * __swahb32 - return a high and low byte-swapped 32-bit value
 * @x: value to byteswap
 *
 * __swahb32(0x12345678) is 0x34127856
 */
#define __swahb32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahb32(x) :		\
	__fswahb32(x))

/**
 * __swab16p - return a byteswapped 16-bit value from a pointer
 * @p: pointer to a naturally-aligned 16-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 154,
  "endLine": 161,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab16p",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u16 *p"
  ],
  "output": "static__inline____u16",
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
    "static __inline__ __u16 __swab16p (const __u16 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab16p\n",
    "    return __arch_swab16p (p);\n",
    "\n",
    "#else\n",
    "    return __swab16 (*p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swab16p",
    "__swab16"
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
static __inline__ __u16 __swab16p(const __u16 *p)
{
#ifdef __arch_swab16p
	return __arch_swab16p(p);
#else
	return __swab16(*p);
#endif
}

/**
 * __swab32p - return a byteswapped 32-bit value from a pointer
 * @p: pointer to a naturally-aligned 32-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 167,
  "endLine": 174,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab32p",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *p"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __swab32p (const __u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab32p\n",
    "    return __arch_swab32p (p);\n",
    "\n",
    "#else\n",
    "    return __swab32 (*p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab32",
    "__arch_swab32p"
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
static __inline__ __u32 __swab32p(const __u32 *p)
{
#ifdef __arch_swab32p
	return __arch_swab32p(p);
#else
	return __swab32(*p);
#endif
}

/**
 * __swab64p - return a byteswapped 64-bit value from a pointer
 * @p: pointer to a naturally-aligned 64-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 180,
  "endLine": 187,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab64p",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u64 *p"
  ],
  "output": "static__inline____u64",
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
    "static __inline__ __u64 __swab64p (const __u64 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab64p\n",
    "    return __arch_swab64p (p);\n",
    "\n",
    "#else\n",
    "    return __swab64 (*p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab64",
    "__arch_swab64p"
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
static __inline__ __u64 __swab64p(const __u64 *p)
{
#ifdef __arch_swab64p
	return __arch_swab64p(p);
#else
	return __swab64(*p);
#endif
}

/**
 * __swahw32p - return a wordswapped 32-bit value from a pointer
 * @p: pointer to a naturally-aligned 32-bit value
 *
 * See __swahw32() for details of wordswapping.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 195,
  "endLine": 202,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swahw32p",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *p"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __swahw32p (const __u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahw32p\n",
    "    return __arch_swahw32p (p);\n",
    "\n",
    "#else\n",
    "    return __swahw32 (*p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swahw32p",
    "__swahw32"
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
static __inline__ __u32 __swahw32p(const __u32 *p)
{
#ifdef __arch_swahw32p
	return __arch_swahw32p(p);
#else
	return __swahw32(*p);
#endif
}

/**
 * __swahb32p - return a high and low byteswapped 32-bit value from a pointer
 * @p: pointer to a naturally-aligned 32-bit value
 *
 * See __swahb32() for details of high/low byteswapping.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 210,
  "endLine": 217,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swahb32p",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *p"
  ],
  "output": "static__inline____u32",
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
    "static __inline__ __u32 __swahb32p (const __u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahb32p\n",
    "    return __arch_swahb32p (p);\n",
    "\n",
    "#else\n",
    "    return __swahb32 (*p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__swahb32",
    "__arch_swahb32p"
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
static __inline__ __u32 __swahb32p(const __u32 *p)
{
#ifdef __arch_swahb32p
	return __arch_swahb32p(p);
#else
	return __swahb32(*p);
#endif
}

/**
 * __swab16s - byteswap a 16-bit value in-place
 * @p: pointer to a naturally-aligned 16-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 223,
  "endLine": 230,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab16s",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 *p"
  ],
  "output": "static__inline__void",
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
    "static __inline__ void __swab16s (__u16 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab16s\n",
    "    __arch_swab16s (p);\n",
    "\n",
    "#else\n",
    "    *p = __swab16p (p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab16p",
    "__arch_swab16s"
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
static __inline__ void __swab16s(__u16 *p)
{
#ifdef __arch_swab16s
	__arch_swab16s(p);
#else
	*p = __swab16p(p);
#endif
}
/**
 * __swab32s - byteswap a 32-bit value in-place
 * @p: pointer to a naturally-aligned 32-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 235,
  "endLine": 242,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab32s",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 *p"
  ],
  "output": "static__inline__void",
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
    "static __inline__ void __swab32s (__u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab32s\n",
    "    __arch_swab32s (p);\n",
    "\n",
    "#else\n",
    "    *p = __swab32p (p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swab32s",
    "__swab32p"
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
static __inline__ void __swab32s(__u32 *p)
{
#ifdef __arch_swab32s
	__arch_swab32s(p);
#else
	*p = __swab32p(p);
#endif
}

/**
 * __swab64s - byteswap a 64-bit value in-place
 * @p: pointer to a naturally-aligned 64-bit value
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 248,
  "endLine": 255,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swab64s",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u64 *p"
  ],
  "output": "static__inline__void",
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
    "static __inline__ void __swab64s (__u64 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swab64s\n",
    "    __arch_swab64s (p);\n",
    "\n",
    "#else\n",
    "    *p = __swab64p (p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swab64s",
    "__swab64p"
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
static __inline__ void __swab64s(__u64 *p)
{
#ifdef __arch_swab64s
	__arch_swab64s(p);
#else
	*p = __swab64p(p);
#endif
}

/**
 * __swahw32s - wordswap a 32-bit value in-place
 * @p: pointer to a naturally-aligned 32-bit value
 *
 * See __swahw32() for details of wordswapping
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 263,
  "endLine": 270,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swahw32s",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 *p"
  ],
  "output": "static__inline__void",
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
    "static __inline__ void __swahw32s (__u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahw32s\n",
    "    __arch_swahw32s (p);\n",
    "\n",
    "#else\n",
    "    *p = __swahw32p (p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__arch_swahw32s",
    "__swahw32p"
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
static __inline__ void __swahw32s(__u32 *p)
{
#ifdef __arch_swahw32s
	__arch_swahw32s(p);
#else
	*p = __swahw32p(p);
#endif
}

/**
 * __swahb32s - high and low byteswap a 32-bit value in-place
 * @p: pointer to a naturally-aligned 32-bit value
 *
 * See __swahb32() for details of high and low byte swapping
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 278,
  "endLine": 285,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/swab.h",
  "funcName": "__swahb32s",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 *p"
  ],
  "output": "static__inline__void",
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
    "static __inline__ void __swahb32s (__u32 *p)\n",
    "{\n",
    "\n",
    "#ifdef __arch_swahb32s\n",
    "    __arch_swahb32s (p);\n",
    "\n",
    "#else\n",
    "    *p = __swahb32p (p);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__swahb32p",
    "__arch_swahb32s"
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
static __inline__ void __swahb32s(__u32 *p)
{
#ifdef __arch_swahb32s
	__arch_swahb32s(p);
#else
	*p = __swahb32p(p);
#endif
}


#endif /* _LINUX_SWAB_H */
