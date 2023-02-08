/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CTX_COMMON_H_
#define __BPF_CTX_COMMON_H_

#include <linux/types.h>
#include <linux/bpf.h>

#include "../compiler.h"
#include "../errno.h"

#define __ctx_skb		1
#define __ctx_xdp		2

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 16,
  "endLine": 19,
  "File": "/home/palani/github/opened_extraction/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "*ctx_data",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinevoid",
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
static __always_inline void *ctx_data(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 24,
  "File": "/home/palani/github/opened_extraction/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "*ctx_data_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinevoid",
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
static __always_inline void *ctx_data_meta(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_meta;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 26,
  "endLine": 29,
  "File": "/home/palani/github/opened_extraction/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "*ctx_data_end",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinevoid",
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
static __always_inline void *ctx_data_end(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_end;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 34,
  "File": "/home/palani/github/opened_extraction/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "ctx_no_room",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *needed",
    " const void *limit"
  ],
  "output": "static__always_inlinebool",
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
static __always_inline bool ctx_no_room(const void *needed, const void *limit)
{
	return unlikely(needed > limit);
}

#endif /* __BPF_CTX_COMMON_H_ */
