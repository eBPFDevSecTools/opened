/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ETH__
#define __LIB_ETH__

#include <linux/if_ether.h>

#ifndef ETH_HLEN
#define ETH_HLEN __ETH_HLEN
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

union macaddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 25,
  "endLine": 35,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_addrcmp",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of Cilium */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union macaddr *a",
    " const union macaddr *b"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_addrcmp (const union macaddr *a, const union macaddr *b)\n",
    "{\n",
    "    int tmp;\n",
    "    tmp = a->p1 - b->p1;\n",
    "    if (!tmp)\n",
    "        tmp = a->p2 - b->p2;\n",
    "    return tmp;\n",
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
static __always_inline int eth_addrcmp(const union macaddr *a,
				       const union macaddr *b)
{
	int tmp;

	tmp = a->p1 - b->p1;
	if (!tmp)
		tmp = a->p2 - b->p2;

	return tmp;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 37,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_is_bcast",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union macaddr *a"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_is_bcast (const union macaddr *a)\n",
    "{\n",
    "    union macaddr bcast;\n",
    "    bcast.p1 = 0xffffffff;\n",
    "    bcast.p2 = 0xffff;\n",
    "    if (!eth_addrcmp (a, &bcast))\n",
    "        return 1;\n",
    "    else\n",
    "        return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "eth_addrcmp"
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
static __always_inline int eth_is_bcast(const union macaddr *a)
{
	union macaddr bcast;

	bcast.p1 = 0xffffffff;
	bcast.p2 = 0xffff;

	if (!eth_addrcmp(a, &bcast))
		return 1;
	else
		return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 54,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_load_saddr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_load_saddr (struct  __ctx_buff *ctx, __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off + ETH_ALEN, mac, ETH_ALEN);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes"
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
static __always_inline int eth_load_saddr(struct __ctx_buff *ctx, __u8 *mac,
					  int off)
{
	return ctx_load_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 56,
  "endLine": 60,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_store_saddr_aligned",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_store_saddr_aligned (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes"
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
static __always_inline int eth_store_saddr_aligned(struct __ctx_buff *ctx,
						   const __u8 *mac, int off)
{
	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 62,
  "endLine": 79,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_store_saddr",
  "developer_inline_comments": [
    {
      "start_line": 12,
      "end_line": 14,
      "text": "/* Need to use builtin here since mac came potentially from\n\t * struct bpf_fib_lookup where it's not aligned on stack. :(\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_store_saddr (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "\n",
    "#if !CTX_DIRECT_WRITE_OK\n",
    "    return eth_store_saddr_aligned (ctx, mac, off);\n",
    "\n",
    "#else\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    if (ctx_no_room (data + off + ETH_ALEN * 2, data_end))\n",
    "        return -EFAULT;\n",
    "    __bpf_memcpy_builtin (data + off + ETH_ALEN, mac, ETH_ALEN);\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_no_room",
    "ctx_data",
    "ctx_data_end",
    "eth_store_saddr_aligned",
    "__bpf_memcpy_builtin"
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
static __always_inline int eth_store_saddr(struct __ctx_buff *ctx,
					   const __u8 *mac, int off)
{
#if !CTX_DIRECT_WRITE_OK
	return eth_store_saddr_aligned(ctx, mac, off);
#else
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);

	if (ctx_no_room(data + off + ETH_ALEN * 2, data_end))
		return -EFAULT;
	/* Need to use builtin here since mac came potentially from
	 * struct bpf_fib_lookup where it's not aligned on stack. :(
	 */
	__bpf_memcpy_builtin(data + off + ETH_ALEN, mac, ETH_ALEN);
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 81,
  "endLine": 85,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_load_daddr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_load_daddr (struct  __ctx_buff *ctx, __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off, mac, ETH_ALEN);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes"
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
static __always_inline int eth_load_daddr(struct __ctx_buff *ctx, __u8 *mac,
					  int off)
{
	return ctx_load_bytes(ctx, off, mac, ETH_ALEN);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 87,
  "endLine": 91,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_store_daddr_aligned",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_store_daddr_aligned (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off, mac, ETH_ALEN, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes"
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
static __always_inline int eth_store_daddr_aligned(struct __ctx_buff *ctx,
						   const __u8 *mac, int off)
{
	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 93,
  "endLine": 110,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_store_daddr",
  "developer_inline_comments": [
    {
      "start_line": 12,
      "end_line": 14,
      "text": "/* Need to use builtin here since mac came potentially from\n\t * struct bpf_fib_lookup where it's not aligned on stack. :(\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u8 *mac",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_store_daddr (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "\n",
    "#if !CTX_DIRECT_WRITE_OK\n",
    "    return eth_store_daddr_aligned (ctx, mac, off);\n",
    "\n",
    "#else\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    if (ctx_no_room (data + off + ETH_ALEN, data_end))\n",
    "        return -EFAULT;\n",
    "    __bpf_memcpy_builtin (data + off, mac, ETH_ALEN);\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_no_room",
    "eth_store_daddr_aligned",
    "ctx_data",
    "ctx_data_end",
    "__bpf_memcpy_builtin"
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
static __always_inline int eth_store_daddr(struct __ctx_buff *ctx,
					   const __u8 *mac, int off)
{
#if !CTX_DIRECT_WRITE_OK
	return eth_store_daddr_aligned(ctx, mac, off);
#else
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);

	if (ctx_no_room(data + off + ETH_ALEN, data_end))
		return -EFAULT;
	/* Need to use builtin here since mac came potentially from
	 * struct bpf_fib_lookup where it's not aligned on stack. :(
	 */
	__bpf_memcpy_builtin(data + off, mac, ETH_ALEN);
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 112,
  "endLine": 117,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eth.h",
  "funcName": "eth_store_proto",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u16 proto",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_store_proto (struct  __ctx_buff *ctx, const __u16 proto, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off + ETH_ALEN + ETH_ALEN, &proto, sizeof (proto), 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes"
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
static __always_inline int eth_store_proto(struct __ctx_buff *ctx,
					   const __u16 proto, int off)
{
	return ctx_store_bytes(ctx, off + ETH_ALEN + ETH_ALEN,
			       &proto, sizeof(proto), 0);
}

#endif /* __LIB_ETH__ */
