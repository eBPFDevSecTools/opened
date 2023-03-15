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
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void bpf_clear_meta (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
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
    "static __always_inline __maybe_unused int get_identity (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 ip_endpoint __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_dip (struct xdp_md * ctx __maybe_unused, __u32 ip_endpoint __maybe_unused)\n",
    "{\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 identity __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_identity_mark (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused)\n",
    "{\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u32 identity __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_identity_meta (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused)\n",
    "{\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u8 key __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_key_mark (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused)\n",
    "{\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " __u8 key __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void set_encrypt_key_meta (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused)\n",
    "{\n",
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
set_encrypt_key_meta(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_alter_or_redo_processing_or_interface",
      "pkt_alter_or_redo_processing_or_interface": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_TX",
          "Return": 3,
          "Description": "an efficient option to transmit the network packet out of the same NIC it just arrived on again. This is typically useful when few nodes are implementing, for example, firewalling with subsequent load balancing in a cluster and thus act as a hairpinned load balancer pushing the incoming packets back into the switch after rewriting them in XDP BPF.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_alter_or_redo_processing_or_interface"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 45,
  "endLine": 53,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h",
  "funcName": "redirect_self",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect",
    "XDP_TX"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* tail call recirculation */"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* xdp -> skb meta transfer */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_skip_nodeport_clear (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx_store_meta (ctx, RECIRC_MARKER, 0);\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_skip_nodeport_set (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    ctx_store_meta (ctx, RECIRC_MARKER, 1);\n",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
  "developer_inline_comments": [
    {
      "start_line": 4,
      "end_line": 4,
      "text": "/* Only intended for SKB context. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unused__u32",
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
    "static __always_inline __maybe_unused __u32 ctx_get_xfer (struct xdp_md * ctx __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_no_room",
    "ctx_data",
    "ctx_data_meta"
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " __u32 meta"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_set_xfer (struct xdp_md *ctx, __u32 meta)\n",
    "{\n",
    "    ctx_store_meta (ctx, XFER_MARKER, meta);\n",
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
  "developer_inline_comments": [
    {
      "start_line": 6,
      "end_line": 6,
      "text": "/* Only intended for SKB context. */"
    }
  ],
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
    "static __always_inline __maybe_unused int ctx_change_head (struct xdp_md * ctx __maybe_unused, __u32 head_room __maybe_unused, __u64 flags __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
