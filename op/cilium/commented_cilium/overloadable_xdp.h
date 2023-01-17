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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "bpf_clear_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "get_identity",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
    "xdp",
    "sched_cls",
    "lwt_xmit",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport_clear",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport_set",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_skip_nodeport",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "ctx_get_xfer",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unused__u32",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
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
static __always_inline __maybe_unused int
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
