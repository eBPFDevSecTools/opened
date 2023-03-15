/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_SKB_H_
#define __LIB_OVERLOADABLE_SKB_H_

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 7,
  "endLine": 17,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "bpf_clear_meta",
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
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void bpf_clear_meta (struct  __sk_buff *ctx)\n",
    "{\n",
    "    __u32 zero = 0;\n",
    "    WRITE_ONCE (ctx->cb[0], zero);\n",
    "    WRITE_ONCE (ctx->cb[1], zero);\n",
    "    WRITE_ONCE (ctx->cb[2], zero);\n",
    "    WRITE_ONCE (ctx->cb[3], zero);\n",
    "    WRITE_ONCE (ctx->cb[4], zero);\n",
    "}\n"
  ],
  "called_function_list": [
    "WRITE_ONCE"
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
static __always_inline __maybe_unused void
bpf_clear_meta(struct __sk_buff *ctx)
{
	__u32 zero = 0;

	WRITE_ONCE(ctx->cb[0], zero);
	WRITE_ONCE(ctx->cb[1], zero);
	WRITE_ONCE(ctx->cb[2], zero);
	WRITE_ONCE(ctx->cb[3], zero);
	WRITE_ONCE(ctx->cb[4], zero);
}

/**
 * get_identity - returns source identity from the mark field
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 26,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "get_identity",
  "developer_inline_comments": [
    {
      "start_line": 19,
      "end_line": 21,
      "text": "/**\n * get_identity - returns source identity from the mark field\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused int get_identity (const struct  __sk_buff *ctx)\n",
    "{\n",
    "    return ((ctx->mark & 0xFF) << 16) | ctx->mark >> 16;\n",
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
static __always_inline __maybe_unused int
get_identity(const struct __sk_buff *ctx)
{
	return ((ctx->mark & 0xFF) << 16) | ctx->mark >> 16;
}

/**
 * get_epid - returns source endpoint identity from the mark field
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 35,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "get_epid",
  "developer_inline_comments": [
    {
      "start_line": 28,
      "end_line": 30,
      "text": "/**\n * get_epid - returns source endpoint identity from the mark field\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u32 get_epid (const struct  __sk_buff *ctx)\n",
    "{\n",
    "    return ctx->mark >> 16;\n",
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
static __always_inline __maybe_unused __u32
get_epid(const struct __sk_buff *ctx)
{
	return ctx->mark >> 16;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 37,
  "endLine": 41,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_encrypt_dip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u32 ip_endpoint"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_encrypt_dip (struct  __sk_buff *ctx, __u32 ip_endpoint)\n",
    "{\n",
    "    ctx->cb[4] = ip_endpoint;\n",
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
static __always_inline __maybe_unused void
set_encrypt_dip(struct __sk_buff *ctx, __u32 ip_endpoint)
{
	ctx->cb[4] = ip_endpoint;
}

/**
 * set_identity_mark - pushes 24 bit identity into ctx mark value.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 51,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_identity_mark",
  "developer_inline_comments": [
    {
      "start_line": 43,
      "end_line": 45,
      "text": "/**\n * set_identity_mark - pushes 24 bit identity into ctx mark value.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u32 identity"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_identity_mark (struct  __sk_buff *ctx, __u32 identity)\n",
    "{\n",
    "    ctx->mark = ctx->mark & MARK_MAGIC_KEY_MASK;\n",
    "    ctx->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);\n",
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
static __always_inline __maybe_unused void
set_identity_mark(struct __sk_buff *ctx, __u32 identity)
{
	ctx->mark = ctx->mark & MARK_MAGIC_KEY_MASK;
	ctx->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 53,
  "endLine": 57,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_identity_meta",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u32 identity"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_identity_meta (struct  __sk_buff *ctx, __u32 identity)\n",
    "{\n",
    "    ctx->cb[1] = identity;\n",
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
static __always_inline __maybe_unused void
set_identity_meta(struct __sk_buff *ctx, __u32 identity)
{
	ctx->cb[1] = identity;
}

/**
 * set_encrypt_key - pushes 8 bit key and encryption marker into ctx mark value.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 62,
  "endLine": 66,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_encrypt_key_mark",
  "developer_inline_comments": [
    {
      "start_line": 59,
      "end_line": 61,
      "text": "/**\n * set_encrypt_key - pushes 8 bit key and encryption marker into ctx mark value.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u8 key"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_encrypt_key_mark (struct  __sk_buff *ctx, __u8 key)\n",
    "{\n",
    "    ctx->mark = or_encrypt_key (key);\n",
    "}\n"
  ],
  "called_function_list": [
    "or_encrypt_key"
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
static __always_inline __maybe_unused void
set_encrypt_key_mark(struct __sk_buff *ctx, __u8 key)
{
	ctx->mark = or_encrypt_key(key);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 68,
  "endLine": 72,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_encrypt_key_meta",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u8 key"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_encrypt_key_meta (struct  __sk_buff *ctx, __u8 key)\n",
    "{\n",
    "    ctx->cb[0] = or_encrypt_key (key);\n",
    "}\n"
  ],
  "called_function_list": [
    "or_encrypt_key"
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
static __always_inline __maybe_unused void
set_encrypt_key_meta(struct __sk_buff *ctx, __u8 key)
{
	ctx->cb[0] = or_encrypt_key(key);
}

/**
 * set_encrypt_mark - sets the encryption mark to make skb to match ip rule
 * used to steer packet into Wireguard tunnel device (cilium_wg0) in order to
 * encrypt it.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 79,
  "endLine": 83,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "set_encrypt_mark",
  "developer_inline_comments": [
    {
      "start_line": 74,
      "end_line": 78,
      "text": "/**\n * set_encrypt_mark - sets the encryption mark to make skb to match ip rule\n * used to steer packet into Wireguard tunnel device (cilium_wg0) in order to\n * encrypt it.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void set_encrypt_mark (struct  __sk_buff *ctx)\n",
    "{\n",
    "    ctx->mark |= MARK_MAGIC_ENCRYPT;\n",
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
static __always_inline __maybe_unused void
set_encrypt_mark(struct __sk_buff *ctx)
{
	ctx->mark |= MARK_MAGIC_ENCRYPT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 85,
  "endLine": 99,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "redirect_self",
  "developer_inline_comments": [
    {
      "start_line": 88,
      "end_line": 93,
      "text": "/* Looping back the packet into the originating netns. In\n\t * case of veth, it's xmit'ing into the hosts' veth device\n\t * such that we end up on ingress in the peer. For ipvlan\n\t * slave it's redirect to ingress as we are attached on the\n\t * slave in netns already.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline __maybe_unused int redirect_self (const struct  __sk_buff *ctx)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_HOST_REDIRECT\n",
    "    return ctx_redirect (ctx, ctx->ifindex, 0);\n",
    "\n",
    "#else\n",
    "    return ctx_redirect (ctx, ctx->ifindex, BPF_F_INGRESS);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_redirect"
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
static __always_inline __maybe_unused int
redirect_self(const struct __sk_buff *ctx)
{
	/* Looping back the packet into the originating netns. In
	 * case of veth, it's xmit'ing into the hosts' veth device
	 * such that we end up on ingress in the peer. For ipvlan
	 * slave it's redirect to ingress as we are attached on the
	 * slave in netns already.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return ctx_redirect(ctx, ctx->ifindex, 0);
#else
	return ctx_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 101,
  "endLine": 107,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_skip_nodeport_clear",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void ctx_skip_nodeport_clear (struct  __sk_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta"
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
static __always_inline __maybe_unused void
ctx_skip_nodeport_clear(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 109,
  "endLine": 115,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_skip_nodeport_set",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void ctx_skip_nodeport_set (struct  __sk_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx->tc_index |= TC_INDEX_F_SKIP_NODEPORT;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta"
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
static __always_inline __maybe_unused void
ctx_skip_nodeport_set(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 117,
  "endLine": 127,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_skip_nodeport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedbool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused bool ctx_skip_nodeport (struct  __sk_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    volatile __u32 tc_index = ctx->tc_index;\n",
    "    ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;\n",
    "    return tc_index & TC_INDEX_F_SKIP_NODEPORT;\n",
    "\n",
    "#else\n",
    "    return true;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_meta"
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
static __always_inline __maybe_unused bool
ctx_skip_nodeport(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	volatile __u32 tc_index = ctx->tc_index;
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
#else
	return true;
#endif
}

#ifdef ENABLE_HOST_FIREWALL
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 130,
  "endLine": 134,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_skip_host_fw_set",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline void ctx_skip_host_fw_set (struct  __sk_buff *ctx)\n",
    "{\n",
    "    ctx->tc_index |= TC_INDEX_F_SKIP_HOST_FIREWALL;\n",
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
static __always_inline void
ctx_skip_host_fw_set(struct __sk_buff *ctx)
{
	ctx->tc_index |= TC_INDEX_F_SKIP_HOST_FIREWALL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 136,
  "endLine": 143,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_skip_host_fw",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline bool ctx_skip_host_fw (struct  __sk_buff *ctx)\n",
    "{\n",
    "    volatile __u32 tc_index = ctx->tc_index;\n",
    "    ctx->tc_index &= ~TC_INDEX_F_SKIP_HOST_FIREWALL;\n",
    "    return tc_index & TC_INDEX_F_SKIP_HOST_FIREWALL;\n",
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
static __always_inline bool
ctx_skip_host_fw(struct __sk_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;

	ctx->tc_index &= ~TC_INDEX_F_SKIP_HOST_FIREWALL;
	return tc_index & TC_INDEX_F_SKIP_HOST_FIREWALL;
}
#endif /* ENABLE_HOST_FIREWALL */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 146,
  "endLine": 152,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_get_xfer",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u32 ctx_get_xfer (struct  __sk_buff *ctx)\n",
    "{\n",
    "    __u32 *data_meta = ctx_data_meta (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    return !ctx_no_room (data_meta + 1, data) ? data_meta[0] : 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_data_meta",
    "ctx_data",
    "ctx_no_room"
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
static __always_inline __maybe_unused __u32 ctx_get_xfer(struct __sk_buff *ctx)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	return !ctx_no_room(data_meta + 1, data) ? data_meta[0] : 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 154,
  "endLine": 158,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_set_xfer",
  "developer_inline_comments": [
    {
      "start_line": 157,
      "end_line": 157,
      "text": "/* Only possible from XDP -> SKB. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff * ctx __maybe_unused",
    " __u32 meta __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void ctx_set_xfer (struct  __sk_buff * ctx __maybe_unused, __u32 meta __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta"
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
static __always_inline __maybe_unused void
ctx_set_xfer(struct __sk_buff *ctx __maybe_unused, __u32 meta __maybe_unused)
{
	/* Only possible from XDP -> SKB. */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Grows headroom of packet associated to <[ skb ]>(IP: 0) and adjusts the offset of the MAC header accordingly , adding <[ len ]>(IP: 1) bytes of space. It automatically extends and reallocates memory as required. This helper can be used on a layer 3 <[ skb ]>(IP: 0) to push a MAC header for redirection into a layer 2 device. All values for <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "skb_change_head",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 160,
  "endLine": 164,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h",
  "funcName": "ctx_change_head",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u32 head_room",
    " __u64 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "skb_change_head"
  ],
  "compatibleHookpoints": [
    "sk_skb",
    "sched_cls",
    "sched_act",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_change_head (struct  __sk_buff *ctx, __u32 head_room, __u64 flags)\n",
    "{\n",
    "    return skb_change_head (ctx, head_room, flags);\n",
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
static __always_inline __maybe_unused int
ctx_change_head(struct __sk_buff *ctx, __u32 head_room, __u64 flags)
{
	return skb_change_head(ctx, head_room, flags);
}

#endif /* __LIB_OVERLOADABLE_SKB_H_ */
