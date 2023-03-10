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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union macaddr *a",
    " const union macaddr *b"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_addrcmp (const union macaddr *a, const union macaddr *b)\n",
    "{\n",
    "    int tmp;\n",
    "    tmp = a->p1 - b->p1;\n",
    "    if (!tmp)\n",
    "        tmp = a->p2 - b->p2;\n",
    "    return tmp;\n",
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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union macaddr *a"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int eth_load_saddr (struct  __ctx_buff *ctx, __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off + ETH_ALEN, mac, ETH_ALEN);\n",
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
    "static __always_inline int eth_store_saddr_aligned (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);\n",
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
    "static __always_inline int eth_load_daddr (struct  __ctx_buff *ctx, __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off, mac, ETH_ALEN);\n",
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
    "static __always_inline int eth_store_daddr_aligned (struct  __ctx_buff *ctx, const __u8 *mac, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off, mac, ETH_ALEN, 0);\n",
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
    "static __always_inline int eth_store_proto (struct  __ctx_buff *ctx, const __u16 proto, int off)\n",
    "{\n",
    "    return ctx_store_bytes (ctx, off + ETH_ALEN + ETH_ALEN, &proto, sizeof (proto), 0);\n",
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
static __always_inline int eth_store_proto(struct __ctx_buff *ctx,
					   const __u16 proto, int off)
{
	return ctx_store_bytes(ctx, off + ETH_ALEN + ETH_ALEN,
			       &proto, sizeof(proto), 0);
}

#endif /* __LIB_ETH__ */
