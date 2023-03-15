/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 7,
  "endLine": 10,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "bpf_clear_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void bpf_clear_meta (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
bpf_clear_meta(struct xdp_md *ctx __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 12,
  "endLine": 16,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "get_identity",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
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
    "static __always_inline __maybe_unused int get_identity (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
static __always_inline __maybe_unused int
get_identity(struct xdp_md *ctx __maybe_unused)
{
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 22,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "set_encrypt_dip",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 ip_endpoint __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_dip (struct xdp_md * ctx __maybe_unused, __u32 ip_endpoint __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
set_encrypt_dip(struct xdp_md *ctx __maybe_unused,
		__u32 ip_endpoint __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 27,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "set_identity_mark",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 identity __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_identity_mark (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
set_identity_mark(struct xdp_md *ctx __maybe_unused, __u32 identity __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 29,
  "endLine": 33,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "set_identity_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 identity __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_identity_meta (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
set_identity_meta(struct xdp_md *ctx __maybe_unused,
		__u32 identity __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 35,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "set_encrypt_key_mark",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u8 key __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_key_mark (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
set_encrypt_key_mark(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 40,
  "endLine": 43,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "set_encrypt_key_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u8 key __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_key_meta (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused)\n",
    "{\n",
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
static __always_inline __maybe_unused void
set_encrypt_key_meta(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "_selfstruct xdp_md *ctx __maybe_unused"
        ]
      }
    ]
  },
  "startLine": 45,
  "endLine": 53,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "redirect_self",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __maybe_unused int redirect_self (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_HOST_REDIRECT\n",
    "    return XDP_TX;\n",
    "\n",
    "#else\n",
    "    return -ENOTSUP;\n",
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
static __always_inline __maybe_unused int
redirect_self(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_REDIRECT
	return XDP_TX;
#else
	return -ENOTSUP;
#endif
}

#define RECIRC_MARKER	5 /* tail call recirculation */
#define XFER_MARKER	6 /* xdp -> skb meta transfer */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 58,
  "endLine": 64,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport_clear",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_skip_nodeport_clear (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx_store_meta (ctx, RECIRC_MARKER, 0);\n",
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
static __always_inline __maybe_unused void
ctx_skip_nodeport_clear(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 0);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 66,
  "endLine": 72,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport_set",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_skip_nodeport_set (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx_store_meta (ctx, RECIRC_MARKER, 1);\n",
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
static __always_inline __maybe_unused void
ctx_skip_nodeport_set(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 1);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 74,
  "endLine": 82,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool ctx_skip_nodeport (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    return ctx_load_meta (ctx, RECIRC_MARKER);\n",
    "\n",
    "#else\n",
    "    return true;\n",
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
static __always_inline __maybe_unused bool
ctx_skip_nodeport(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return ctx_load_meta(ctx, RECIRC_MARKER);
#else
	return true;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 84,
  "endLine": 88,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_get_xfer",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unused__u32",
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
    "static __always_inline __maybe_unused __u32 ctx_get_xfer (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
static __always_inline __maybe_unused __u32
ctx_get_xfer(struct xdp_md *ctx __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 90,
  "endLine": 94,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_set_xfer",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " __u32 meta"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_set_xfer (struct xdp_md *ctx, __u32 meta)\n",
    "{\n",
    "    ctx_store_meta (ctx, XFER_MARKER, meta);\n",
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
static __always_inline __maybe_unused void ctx_set_xfer(struct xdp_md *ctx,
							__u32 meta)
{
	ctx_store_meta(ctx, XFER_MARKER, meta);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 96,
  "endLine": 102,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_change_head",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 head_room __maybe_unused",
    " __u64 flags __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
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
    "static __always_inline __maybe_unused int ctx_change_head (struct xdp_md * ctx __maybe_unused, __u32 head_room __maybe_unused, __u64 flags __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
static __always_inline __maybe_unused int
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */