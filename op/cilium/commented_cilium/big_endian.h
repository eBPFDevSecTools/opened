/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef _LINUX_BYTEORDER_BIG_ENDIAN_H
#define _LINUX_BYTEORDER_BIG_ENDIAN_H

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __BIG_ENDIAN_BITFIELD
#define __BIG_ENDIAN_BITFIELD
#endif

#include <linux/types.h>
#include <linux/swab.h>

#define __constant_htonl(x) ((__be32)(__u32)(x))
#define __constant_ntohl(x) ((__u32)(__be32)(x))
#define __constant_htons(x) ((__be16)(__u16)(x))
#define __constant_ntohs(x) ((__u16)(__be16)(x))
#define __constant_cpu_to_le64(x) ((__le64)___constant_swab64((x)))
#define __constant_le64_to_cpu(x) ___constant_swab64((__u64)(__le64)(x))
#define __constant_cpu_to_le32(x) ((__le32)___constant_swab32((x)))
#define __constant_le32_to_cpu(x) ___constant_swab32((__u32)(__le32)(x))
#define __constant_cpu_to_le16(x) ((__le16)___constant_swab16((x)))
#define __constant_le16_to_cpu(x) ___constant_swab16((__u16)(__le16)(x))
#define __constant_cpu_to_be64(x) ((__be64)(__u64)(x))
#define __constant_be64_to_cpu(x) ((__u64)(__be64)(x))
#define __constant_cpu_to_be32(x) ((__be32)(__u32)(x))
#define __constant_be32_to_cpu(x) ((__u32)(__be32)(x))
#define __constant_cpu_to_be16(x) ((__be16)(__u16)(x))
#define __constant_be16_to_cpu(x) ((__u16)(__be16)(x))
#define __cpu_to_le64(x) ((__le64)__swab64((x)))
#define __le64_to_cpu(x) __swab64((__u64)(__le64)(x))
#define __cpu_to_le32(x) ((__le32)__swab32((x)))
#define __le32_to_cpu(x) __swab32((__u32)(__le32)(x))
#define __cpu_to_le16(x) ((__le16)__swab16((x)))
#define __le16_to_cpu(x) __swab16((__u16)(__le16)(x))
#define __cpu_to_be64(x) ((__be64)(__u64)(x))
#define __be64_to_cpu(x) ((__u64)(__be64)(x))
#define __cpu_to_be32(x) ((__be32)(__u32)(x))
#define __be32_to_cpu(x) ((__u32)(__be32)(x))
#define __cpu_to_be16(x) ((__be16)(__u16)(x))
#define __be16_to_cpu(x) ((__u16)(__be16)(x))

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 45,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_le64p",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of the Linux kernel */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u64 *p"
  ],
  "output": "static__inline____le64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __le64 __cpu_to_le64p (const __u64 *p)\n",
    "{\n",
    "    return (__le64) __swab64p (p);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __le64 __cpu_to_le64p(const __u64 *p)
{
	return (__le64)__swab64p(p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 49,
  "endLine": 52,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__le64_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __le64 *p"
  ],
  "output": "static__inline____u64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u64 __le64_to_cpup (const __le64 *p)\n",
    "{\n",
    "    return __swab64p ((__u64 *) p);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __u64 __le64_to_cpup(const __le64 *p)
{
	return __swab64p((__u64 *)p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 53,
  "endLine": 56,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_le32p",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *p"
  ],
  "output": "static__inline____le32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __le32 __cpu_to_le32p (const __u32 *p)\n",
    "{\n",
    "    return (__le32) __swab32p (p);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __le32 __cpu_to_le32p(const __u32 *p)
{
	return (__le32)__swab32p(p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 60,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__le32_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __le32 *p"
  ],
  "output": "static__inline____u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u32 __le32_to_cpup (const __le32 *p)\n",
    "{\n",
    "    return __swab32p ((__u32 *) p);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __u32 __le32_to_cpup(const __le32 *p)
{
	return __swab32p((__u32 *)p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 61,
  "endLine": 64,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_le16p",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u16 *p"
  ],
  "output": "static__inline____le16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __le16 __cpu_to_le16p (const __u16 *p)\n",
    "{\n",
    "    return (__le16) __swab16p (p);\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab16p"
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
static __inline__ __le16 __cpu_to_le16p(const __u16 *p)
{
	return (__le16)__swab16p(p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 65,
  "endLine": 68,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__le16_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __le16 *p"
  ],
  "output": "static__inline____u16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u16 __le16_to_cpup (const __le16 *p)\n",
    "{\n",
    "    return __swab16p ((__u16 *) p);\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab16p"
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
static __inline__ __u16 __le16_to_cpup(const __le16 *p)
{
	return __swab16p((__u16 *)p);
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 72,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_be64p",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u64 *p"
  ],
  "output": "static__inline____be64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __be64 __cpu_to_be64p (const __u64 *p)\n",
    "{\n",
    "    return (__be64) *p;\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __be64 __cpu_to_be64p(const __u64 *p)
{
	return (__be64)*p;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 73,
  "endLine": 76,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__be64_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __be64 *p"
  ],
  "output": "static__inline____u64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u64 __be64_to_cpup (const __be64 *p)\n",
    "{\n",
    "    return (__u64) *p;\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __u64 __be64_to_cpup(const __be64 *p)
{
	return (__u64)*p;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 77,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_be32p",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u32 *p"
  ],
  "output": "static__inline____be32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __be32 __cpu_to_be32p (const __u32 *p)\n",
    "{\n",
    "    return (__be32) *p;\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __be32 __cpu_to_be32p(const __u32 *p)
{
	return (__be32)*p;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 81,
  "endLine": 84,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__be32_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __be32 *p"
  ],
  "output": "static__inline____u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u32 __be32_to_cpup (const __be32 *p)\n",
    "{\n",
    "    return (__u32) *p;\n",
    "}\n"
  ],
  "called_function_list": [
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
static __inline__ __u32 __be32_to_cpup(const __be32 *p)
{
	return (__u32)*p;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 85,
  "endLine": 88,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__cpu_to_be16p",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __u16 *p"
  ],
  "output": "static__inline____be16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __be16 __cpu_to_be16p (const __u16 *p)\n",
    "{\n",
    "    return (__be16) *p;\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab16p"
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
static __inline__ __be16 __cpu_to_be16p(const __u16 *p)
{
	return (__be16)*p;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 89,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/big_endian.h",
  "funcName": "__be16_to_cpup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const __be16 *p"
  ],
  "output": "static__inline____u16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __inline__ __u16 __be16_to_cpup (const __be16 *p)\n",
    "{\n",
    "    return (__u16) *p;\n",
    "}\n"
  ],
  "called_function_list": [
    "__swab16p"
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
static __inline__ __u16 __be16_to_cpup(const __be16 *p)
{
	return (__u16)*p;
}
#define __cpu_to_le64s(x) __swab64s((x))
#define __le64_to_cpus(x) __swab64s((x))
#define __cpu_to_le32s(x) __swab32s((x))
#define __le32_to_cpus(x) __swab32s((x))
#define __cpu_to_le16s(x) __swab16s((x))
#define __le16_to_cpus(x) __swab16s((x))
#define __cpu_to_be64s(x) do { (void)(x); } while (0)
#define __be64_to_cpus(x) do { (void)(x); } while (0)
#define __cpu_to_be32s(x) do { (void)(x); } while (0)
#define __be32_to_cpus(x) do { (void)(x); } while (0)
#define __cpu_to_be16s(x) do { (void)(x); } while (0)
#define __be16_to_cpus(x) do { (void)(x); } while (0)


#endif /* _LINUX_BYTEORDER_BIG_ENDIAN_H */
