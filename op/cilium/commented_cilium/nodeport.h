/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __NODEPORT_H_
#define __NODEPORT_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "nat.h"
#include "edt.h"
#include "lb.h"
#include "common.h"
#include "overloadable.h"
#include "egress_policies.h"
#include "eps.h"
#include "conntrack.h"
#include "csum.h"
#include "encap.h"
#include "identity.h"
#include "trace.h"
#include "ghash.h"
#include "pcap.h"
#include "host_firewall.h"
#include "stubs.h"
#include "proxy_hairpin.h"

#define CB_SRC_IDENTITY	0

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 35,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "bpf_skip_nodeport_clear",
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
    "struct  __ctx_buff *ctx"
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
    "static __always_inline __maybe_unused void bpf_skip_nodeport_clear (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    ctx_skip_nodeport_clear (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_skip_nodeport_clear"
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
bpf_skip_nodeport_clear(struct __ctx_buff *ctx)
{
	ctx_skip_nodeport_clear(ctx);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 37,
  "endLine": 41,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "bpf_skip_nodeport_set",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
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
    "static __always_inline __maybe_unused void bpf_skip_nodeport_set (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    ctx_skip_nodeport_set (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_skip_nodeport_set"
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
bpf_skip_nodeport_set(struct __ctx_buff *ctx)
{
	ctx_skip_nodeport_set(ctx);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 43,
  "endLine": 47,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "bpf_skip_nodeport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
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
    "static __always_inline __maybe_unused bool bpf_skip_nodeport (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return ctx_skip_nodeport (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_skip_nodeport"
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
bpf_skip_nodeport(struct __ctx_buff *ctx)
{
	return ctx_skip_nodeport(ctx);
}

#ifdef ENABLE_NODEPORT
#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __be32);	/* ipv4 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH4_SIZE);
} NODEPORT_NEIGH4 __section_maps_btf;
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, union v6addr);	/* ipv6 addr */
	__type(value, union macaddr);	/* hw addr */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, NODEPORT_NEIGH6_SIZE);
} NODEPORT_NEIGH6 __section_maps_btf;

/* The IPv6 extension should be 8-bytes aligned */
struct dsr_opt_v6 {
	__u8 nexthdr;
	__u8 len;
	__u8 opt_type;
	__u8 opt_len;
	union v6addr addr;
	__be16 port;
	__u16 pad;
};
#endif /* ENABLE_IPV6 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 81,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_uses_dsr",
  "developer_inline_comments": [
    {
      "start_line": 53,
      "end_line": 53,
      "text": "/* ipv4 addr */"
    },
    {
      "start_line": 54,
      "end_line": 54,
      "text": "/* hw addr */"
    },
    {
      "start_line": 58,
      "end_line": 58,
      "text": "/* ENABLE_IPV4 */"
    },
    {
      "start_line": 63,
      "end_line": 63,
      "text": "/* ipv6 addr */"
    },
    {
      "start_line": 64,
      "end_line": 64,
      "text": "/* hw addr */"
    },
    {
      "start_line": 69,
      "end_line": 69,
      "text": "/* The IPv6 extension should be 8-bytes aligned */"
    },
    {
      "start_line": 79,
      "end_line": 79,
      "text": "/* ENABLE_IPV6 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 nexthdr __maybe_unused"
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
    "static __always_inline bool nodeport_uses_dsr (__u8 nexthdr __maybe_unused)\n",
    "{\n",
    "\n",
    "# if defined(ENABLE_DSR) && !defined(ENABLE_DSR_HYBRID)\n",
    "    return true;\n",
    "\n",
    "# elif defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)\n",
    "    if (nexthdr == IPPROTO_TCP)\n",
    "        return true;\n",
    "    return false;\n",
    "\n",
    "# else\n",
    "    return false;\n",
    "\n",
    "# endif\n",
    "}\n"
  ],
  "called_function_list": [
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
static __always_inline bool nodeport_uses_dsr(__u8 nexthdr __maybe_unused)
{
# if defined(ENABLE_DSR) && !defined(ENABLE_DSR_HYBRID)
	return true;
# elif defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)
	if (nexthdr == IPPROTO_TCP)
		return true;
	return false;
# else
	return false;
# endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 94,
  "endLine": 103,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "bpf_mark_snat_done",
  "developer_inline_comments": [
    {
      "start_line": 97,
      "end_line": 99,
      "text": "/* From XDP layer, we do not go through an egress hook from\n\t * here, hence nothing to be done.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline void bpf_mark_snat_done (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#if __ctx_is == __ctx_skb\n",
    "    ctx->mark |= MARK_MAGIC_SNAT_DONE;\n",
    "\n",
    "#endif\n",
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
bpf_mark_snat_done(struct __ctx_buff *ctx __maybe_unused)
{
	/* From XDP layer, we do not go through an egress hook from
	 * here, hence nothing to be done.
	 */
#if __ctx_is == __ctx_skb
	ctx->mark |= MARK_MAGIC_SNAT_DONE;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 105,
  "endLine": 116,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "bpf_skip_recirculation",
  "developer_inline_comments": [
    {
      "start_line": 108,
      "end_line": 110,
      "text": "/* From XDP layer, we do not go through an egress hook from\n\t * here, hence nothing to be skipped.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline bool bpf_skip_recirculation (const struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#if __ctx_is == __ctx_skb\n",
    "    return ctx->tc_index & TC_INDEX_F_SKIP_RECIRCULATION;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif\n",
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
bpf_skip_recirculation(const struct __ctx_buff *ctx __maybe_unused)
{
	/* From XDP layer, we do not go through an egress hook from
	 * here, hence nothing to be skipped.
	 */
#if __ctx_is == __ctx_skb
	return ctx->tc_index & TC_INDEX_F_SKIP_RECIRCULATION;
#else
	return false;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 118,
  "endLine": 125,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "ctx_adjust_hroom_dsr_flags",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inline__u64",
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
    "static __always_inline __u64 ctx_adjust_hroom_dsr_flags (void)\n",
    "{\n",
    "\n",
    "#ifdef BPF_HAVE_CSUM_LEVEL\n",
    "    return BPF_F_ADJ_ROOM_NO_CSUM_RESET;\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
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
static __always_inline __u64 ctx_adjust_hroom_dsr_flags(void)
{
#ifdef BPF_HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#else
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 127,
  "endLine": 134,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_fail_needs_reply",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int code __maybe_unused"
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
    "static __always_inline bool dsr_fail_needs_reply (int code __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_DSR_ICMP_ERRORS\n",
    "    if (code == DROP_FRAG_NEEDED)\n",
    "        return true;\n",
    "\n",
    "#endif\n",
    "    return false;\n",
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
static __always_inline bool dsr_fail_needs_reply(int code __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	if (code == DROP_FRAG_NEEDED)
		return true;
#endif
	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 136,
  "endLine": 144,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_is_too_big",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u16 expanded_len __maybe_unused"
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
    "static __always_inline bool dsr_is_too_big (struct  __ctx_buff * ctx __maybe_unused, __u16 expanded_len __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_DSR_ICMP_ERRORS\n",
    "    if (expanded_len > THIS_MTU)\n",
    "        return true;\n",
    "\n",
    "#endif\n",
    "    return false;\n",
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
static __always_inline bool dsr_is_too_big(struct __ctx_buff *ctx __maybe_unused,
					   __u16 expanded_len __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	if (expanded_len > THIS_MTU)
		return true;
#endif
	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 146,
  "endLine": 170,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "maybe_add_l2_hdr",
  "developer_inline_comments": [
    {
      "start_line": 152,
      "end_line": 154,
      "text": "/* NodePort request is going to be redirected to L3 dev, so skip\n\t\t * L2 addr settings.\n\t\t */"
    },
    {
      "start_line": 157,
      "end_line": 159,
      "text": "/* NodePort request is going to be redirected from L3 to L2 dev,\n\t\t * so we need to create L2 hdr first.\n\t\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u32 ifindex __maybe_unused",
    " bool * l2_hdr_required __maybe_unused"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int maybe_add_l2_hdr (struct  __ctx_buff * ctx __maybe_unused, __u32 ifindex __maybe_unused, bool * l2_hdr_required __maybe_unused)\n",
    "{\n",
    "    if (IS_L3_DEV (ifindex))\n",
    "        *l2_hdr_required = false;\n",
    "    else if (ETH_HLEN == 0) {\n",
    "        __u16 proto = ctx_get_protocol (ctx);\n",
    "        if (ctx_change_head (ctx, __ETH_HLEN, 0))\n",
    "            return DROP_INVALID;\n",
    "        if (eth_store_proto (ctx, proto, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "eth_store_proto",
    "ctx_get_protocol",
    "IS_L3_DEV",
    "ctx_change_head"
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
static __always_inline int
maybe_add_l2_hdr(struct __ctx_buff *ctx __maybe_unused,
		 __u32 ifindex __maybe_unused,
		 bool *l2_hdr_required __maybe_unused)
{
	if (IS_L3_DEV(ifindex))
		/* NodePort request is going to be redirected to L3 dev, so skip
		 * L2 addr settings.
		 */
		*l2_hdr_required = false;
	else if (ETH_HLEN == 0) {
		/* NodePort request is going to be redirected from L3 to L2 dev,
		 * so we need to create L2 hdr first.
		 */
		__u16 proto = ctx_get_protocol(ctx);

		if (ctx_change_head(ctx, __ETH_HLEN, 0))
			return DROP_INVALID;

		if (eth_store_proto(ctx, proto, 0) < 0)
			return DROP_WRITE_ERROR;
	}

	return 0;
}

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 176,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_uses_dsr6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6_ct_tuple *tuple"
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
    "static __always_inline bool nodeport_uses_dsr6 (const struct ipv6_ct_tuple *tuple)\n",
    "{\n",
    "    return nodeport_uses_dsr (tuple->nexthdr);\n",
    "}\n"
  ],
  "called_function_list": [
    "nodeport_uses_dsr"
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
static __always_inline bool nodeport_uses_dsr6(const struct ipv6_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

/* TODO(brb): after GH#6320, we can move snat_v{4,6}_needed() to lib/nat.h, as
 * then the helper function won't depend the dsr checks.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 181,
  "endLine": 203,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "snat_v6_needed",
  "developer_inline_comments": [
    {
      "start_line": 178,
      "end_line": 180,
      "text": "/* TODO(brb): after GH#6320, we can move snat_v{4,6}_needed() to lib/nat.h, as\n * then the helper function won't depend the dsr checks.\n */"
    },
    {
      "start_line": 200,
      "end_line": 200,
      "text": "/* ENABLE_DSR_HYBRID */"
    },
    {
      "start_line": 201,
      "end_line": 201,
      "text": "/* See snat_v4_needed(). */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *addr"
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
    "static __always_inline bool snat_v6_needed (struct  __ctx_buff *ctx, const union v6addr *addr)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return false;\n",
    "\n",
    "#ifdef ENABLE_DSR_HYBRID\n",
    "    {\n",
    "        __u8 nexthdr = ip6->nexthdr;\n",
    "        int ret;\n",
    "        ret = ipv6_hdrlen (ctx, & nexthdr);\n",
    "        if (ret > 0) {\n",
    "            if (nodeport_uses_dsr (nexthdr))\n",
    "                return false;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_DSR_HYBRID */\n",
    "    return !ipv6_addrcmp ((union v6addr *) &ip6->saddr, addr);\n",
    "}\n"
  ],
  "called_function_list": [
    "nodeport_uses_dsr",
    "ipv6_addrcmp",
    "revalidate_data",
    "ipv6_hdrlen"
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
static __always_inline bool snat_v6_needed(struct __ctx_buff *ctx,
					   const union v6addr *addr)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return false;
#ifdef ENABLE_DSR_HYBRID
	{
		__u8 nexthdr = ip6->nexthdr;
		int ret;

		ret = ipv6_hdrlen(ctx, &nexthdr);
		if (ret > 0) {
			if (nodeport_uses_dsr(nexthdr))
				return false;
		}
	}
#endif /* ENABLE_DSR_HYBRID */
	/* See snat_v4_needed(). */
	return !ipv6_addrcmp((union v6addr *)&ip6->saddr, addr);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 205,
  "endLine": 221,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_nat_ipv6_fwd",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *addr"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int nodeport_nat_ipv6_fwd (struct  __ctx_buff *ctx, const union v6addr *addr)\n",
    "{\n",
    "    struct ipv6_nat_target target = {\n",
    "        .min_port = NODEPORT_PORT_MIN_NAT,\n",
    "        .max_port = NODEPORT_PORT_MAX_NAT,}\n",
    "    ;\n",
    "    int ret;\n",
    "    ipv6_addr_copy (&target.addr, addr);\n",
    "    ret = snat_v6_needed (ctx, addr) ? snat_v6_process (ctx, NAT_DIR_EGRESS, &target) : CTX_ACT_OK;\n",
    "    if (ret == NAT_PUNT_TO_STACK)\n",
    "        ret = CTX_ACT_OK;\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_addr_copy",
    "snat_v6_needed",
    "snat_v6_process"
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
static __always_inline int nodeport_nat_ipv6_fwd(struct __ctx_buff *ctx,
						 const union v6addr *addr)
{
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
	};
	int ret;

	ipv6_addr_copy(&target.addr, addr);

	ret = snat_v6_needed(ctx, addr) ?
	      snat_v6_process(ctx, NAT_DIR_EGRESS, &target) : CTX_ACT_OK;
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;
	return ret;
}

#ifdef ENABLE_DSR
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 225,
  "endLine": 252,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "rss_gen_src6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "union v6addr *src",
    " const union v6addr *client",
    " __be32 l4_hint"
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
    "static __always_inline void rss_gen_src6 (union v6addr *src, const union v6addr *client, __be32 l4_hint)\n",
    "{\n",
    "    __u32 bits = 128 - IPV6_RSS_PREFIX_BITS;\n",
    "    *src = (union v6addr) IPV6_RSS_PREFIX;\n",
    "    if (bits) {\n",
    "        __u32 todo;\n",
    "        if (bits > 96) {\n",
    "            todo = bits - 96;\n",
    "            src->p1 |= bpf_htonl (hash_32 (client->p1 ^ l4_hint, todo));\n",
    "            bits -= todo;\n",
    "        }\n",
    "        if (bits > 64) {\n",
    "            todo = bits - 64;\n",
    "            src->p2 |= bpf_htonl (hash_32 (client->p2 ^ l4_hint, todo));\n",
    "            bits -= todo;\n",
    "        }\n",
    "        if (bits > 32) {\n",
    "            todo = bits - 32;\n",
    "            src->p3 |= bpf_htonl (hash_32 (client->p3 ^ l4_hint, todo));\n",
    "            bits -= todo;\n",
    "        }\n",
    "        src->p4 |= bpf_htonl (hash_32 (client->p4 ^ l4_hint, bits));\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "hash_32",
    "bpf_htonl"
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
static __always_inline void rss_gen_src6(union v6addr *src,
					 const union v6addr *client,
					 __be32 l4_hint)
{
	__u32 bits = 128 - IPV6_RSS_PREFIX_BITS;

	*src = (union v6addr)IPV6_RSS_PREFIX;
	if (bits) {
		__u32 todo;

		if (bits > 96) {
			todo = bits - 96;
			src->p1 |= bpf_htonl(hash_32(client->p1 ^ l4_hint, todo));
			bits -= todo;
		}
		if (bits > 64) {
			todo = bits - 64;
			src->p2 |= bpf_htonl(hash_32(client->p2 ^ l4_hint, todo));
			bits -= todo;
		}
		if (bits > 32) {
			todo = bits - 32;
			src->p3 |= bpf_htonl(hash_32(client->p3 ^ l4_hint, todo));
			bits -= todo;
		}
		src->p4 |= bpf_htonl(hash_32(client->p4 ^ l4_hint, bits));
	}
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 254,
  "endLine": 292,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_set_ipip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ipv6hdr *ip6",
    " const union v6addr *backend_addr",
    " __be32 l4_hint",
    " int *ohead"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int dsr_set_ipip6 (struct  __ctx_buff *ctx, const struct ipv6hdr *ip6, const union v6addr *backend_addr, __be32 l4_hint, int *ohead)\n",
    "{\n",
    "    __u16 payload_len = bpf_ntohs (ip6->payload_len) + sizeof (*ip6);\n",
    "    const int l3_off = ETH_HLEN;\n",
    "    union v6addr saddr;\n",
    "    struct {\n",
    "        __be16 payload_len;\n",
    "        __u8 nexthdr;\n",
    "        __u8 hop_limit;\n",
    "    } tp_new = {\n",
    "        .payload_len = bpf_htons (payload_len),\n",
    "        .nexthdr = IPPROTO_IPV6,\n",
    "        .hop_limit = IPDEFTTL,};\n",
    "\n",
    "    if (dsr_is_too_big (ctx, payload_len + sizeof (*ip6))) {\n",
    "        *ohead = sizeof (*ip6);\n",
    "        return DROP_FRAG_NEEDED;\n",
    "    }\n",
    "    rss_gen_src6 (&saddr, (union v6addr *) &ip6->saddr, l4_hint);\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (*ip6), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct ipv6hdr, payload_len), &tp_new.payload_len, 4, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct ipv6hdr, daddr), backend_addr, sizeof (ip6->daddr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct ipv6hdr, saddr), &saddr, sizeof (ip6->saddr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_adjust_hroom_dsr_flags",
    "dsr_is_too_big",
    "bpf_ntohs",
    "ctx_store_bytes",
    "rss_gen_src6",
    "ctx_adjust_hroom",
    "offsetof",
    "bpf_htons"
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
static __always_inline int dsr_set_ipip6(struct __ctx_buff *ctx,
					 const struct ipv6hdr *ip6,
					 const union v6addr *backend_addr,
					 __be32 l4_hint, int *ohead)
{
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
	const int l3_off = ETH_HLEN;
	union v6addr saddr;
	struct {
		__be16 payload_len;
		__u8 nexthdr;
		__u8 hop_limit;
	} tp_new = {
		.payload_len	= bpf_htons(payload_len),
		.nexthdr	= IPPROTO_IPV6,
		.hop_limit	= IPDEFTTL,
	};

	if (dsr_is_too_big(ctx, payload_len + sizeof(*ip6))) {
		*ohead = sizeof(*ip6);
		return DROP_FRAG_NEEDED;
	}

	rss_gen_src6(&saddr, (union v6addr *)&ip6->saddr, l4_hint);

	if (ctx_adjust_hroom(ctx, sizeof(*ip6), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, payload_len),
			    &tp_new.payload_len, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, daddr),
			    backend_addr, sizeof(ip6->daddr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct ipv6hdr, saddr),
			    &saddr, sizeof(ip6->saddr), 0) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 294,
  "endLine": 327,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_set_ext6",
  "developer_inline_comments": [
    {
      "start_line": 302,
      "end_line": 302,
      "text": "/* The IPv6 extension should be 8-bytes aligned */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6hdr *ip6",
    " const union v6addr *svc_addr",
    " __be16 svc_port",
    " int *ohead"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int dsr_set_ext6 (struct  __ctx_buff *ctx, struct ipv6hdr *ip6, const union v6addr *svc_addr, __be16 svc_port, int *ohead)\n",
    "{\n",
    "    struct dsr_opt_v6 opt __align_stack_8 = {}\n",
    "    ;\n",
    "    __u16 payload_len = bpf_ntohs (ip6->payload_len) + sizeof (opt);\n",
    "    build_bug_on ((sizeof (struct dsr_opt_v6) % 8) != 0);\n",
    "    if (dsr_is_too_big (ctx, payload_len)) {\n",
    "        *ohead = sizeof (opt);\n",
    "        return DROP_FRAG_NEEDED;\n",
    "    }\n",
    "    opt.nexthdr = ip6->nexthdr;\n",
    "    ip6->nexthdr = NEXTHDR_DEST;\n",
    "    ip6->payload_len = bpf_htons (payload_len);\n",
    "    opt.len = DSR_IPV6_EXT_LEN;\n",
    "    opt.opt_type = DSR_IPV6_OPT_TYPE;\n",
    "    opt.opt_len = DSR_IPV6_OPT_LEN;\n",
    "    ipv6_addr_copy (&opt.addr, svc_addr);\n",
    "    opt.port = svc_port;\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (opt), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + sizeof (*ip6), &opt, sizeof (opt), 0) < 0)\n",
    "        return DROP_INVALID;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_adjust_hroom_dsr_flags",
    "dsr_is_too_big",
    "bpf_ntohs",
    "build_bug_on",
    "ctx_store_bytes",
    "ctx_adjust_hroom",
    "ipv6_addr_copy",
    "bpf_htons"
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
static __always_inline int dsr_set_ext6(struct __ctx_buff *ctx,
					struct ipv6hdr *ip6,
					const union v6addr *svc_addr,
					__be16 svc_port, int *ohead)
{
	struct dsr_opt_v6 opt __align_stack_8 = {};
	__u16 payload_len = bpf_ntohs(ip6->payload_len) + sizeof(opt);

	/* The IPv6 extension should be 8-bytes aligned */
	build_bug_on((sizeof(struct dsr_opt_v6) % 8) != 0);

	if (dsr_is_too_big(ctx, payload_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	opt.nexthdr = ip6->nexthdr;
	ip6->nexthdr = NEXTHDR_DEST;
	ip6->payload_len = bpf_htons(payload_len);

	opt.len = DSR_IPV6_EXT_LEN;
	opt.opt_type = DSR_IPV6_OPT_TYPE;
	opt.opt_len = DSR_IPV6_OPT_LEN;
	ipv6_addr_copy(&opt.addr, svc_addr);
	opt.port = svc_port;

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip6), &opt,
			    sizeof(opt), 0) < 0)
		return DROP_INVALID;
	return 0;
}
#endif /* DSR_ENCAP_MODE */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 330,
  "endLine": 378,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "find_dsr_v6",
  "developer_inline_comments": [
    {
      "start_line": 376,
      "end_line": 376,
      "text": "/* Reached limit of supported extension headers */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 nexthdr",
    " struct dsr_opt_v6 *dsr_opt",
    " bool *found"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int find_dsr_v6 (struct  __ctx_buff *ctx, __u8 nexthdr, struct dsr_opt_v6 *dsr_opt, bool *found)\n",
    "{\n",
    "    struct ipv6_opt_hdr opthdr __align_stack_8;\n",
    "    int i, len = sizeof (struct ipv6hdr);\n",
    "    __u8 nh = nexthdr;\n",
    "\n",
    "#pragma unroll\n",
    "    for (i = 0; i < IPV6_MAX_HEADERS; i++) {\n",
    "        switch (nh) {\n",
    "        case NEXTHDR_NONE :\n",
    "            return DROP_INVALID_EXTHDR;\n",
    "        case NEXTHDR_FRAGMENT :\n",
    "            return DROP_FRAG_NOSUPPORT;\n",
    "        case NEXTHDR_HOP :\n",
    "        case NEXTHDR_ROUTING :\n",
    "        case NEXTHDR_AUTH :\n",
    "        case NEXTHDR_DEST :\n",
    "            if (ctx_load_bytes (ctx, ETH_HLEN + len, &opthdr, sizeof (opthdr)) < 0)\n",
    "                return DROP_INVALID;\n",
    "            if (nh == NEXTHDR_DEST && opthdr.hdrlen == DSR_IPV6_EXT_LEN) {\n",
    "                if (ctx_load_bytes (ctx, ETH_HLEN + len, dsr_opt, sizeof (*dsr_opt)) < 0)\n",
    "                    return DROP_INVALID;\n",
    "                if (dsr_opt->opt_type == DSR_IPV6_OPT_TYPE && dsr_opt->opt_len == DSR_IPV6_OPT_LEN) {\n",
    "                    *found = true;\n",
    "                    return 0;\n",
    "                }\n",
    "            }\n",
    "            nh = opthdr.nexthdr;\n",
    "            if (nh == NEXTHDR_AUTH)\n",
    "                len += ipv6_authlen (&opthdr);\n",
    "            else\n",
    "                len += ipv6_optlen (&opthdr);\n",
    "            break;\n",
    "        default :\n",
    "            return 0;\n",
    "        }\n",
    "    }\n",
    "    return DROP_INVALID_EXTHDR;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes",
    "ipv6_authlen",
    "ipv6_optlen"
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
static __always_inline int find_dsr_v6(struct __ctx_buff *ctx, __u8 nexthdr,
				       struct dsr_opt_v6 *dsr_opt, bool *found)
{
	struct ipv6_opt_hdr opthdr __align_stack_8;
	int i, len = sizeof(struct ipv6hdr);
	__u8 nh = nexthdr;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case NEXTHDR_NONE:
			return DROP_INVALID_EXTHDR;

		case NEXTHDR_FRAGMENT:
			return DROP_FRAG_NOSUPPORT;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_AUTH:
		case NEXTHDR_DEST:
			if (ctx_load_bytes(ctx, ETH_HLEN + len, &opthdr, sizeof(opthdr)) < 0)
				return DROP_INVALID;

			if (nh == NEXTHDR_DEST && opthdr.hdrlen == DSR_IPV6_EXT_LEN) {
				if (ctx_load_bytes(ctx, ETH_HLEN + len, dsr_opt,
						   sizeof(*dsr_opt)) < 0)
					return DROP_INVALID;
				if (dsr_opt->opt_type == DSR_IPV6_OPT_TYPE &&
				    dsr_opt->opt_len == DSR_IPV6_OPT_LEN) {
					*found = true;
					return 0;
				}
			}

			nh = opthdr.nexthdr;
			if (nh == NEXTHDR_AUTH)
				len += ipv6_authlen(&opthdr);
			else
				len += ipv6_optlen(&opthdr);
			break;

		default:
			return 0;
		}
	}

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 380,
  "endLine": 400,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "handle_dsr_v6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " bool *dsr"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int handle_dsr_v6 (struct  __ctx_buff *ctx, bool *dsr)\n",
    "{\n",
    "    struct dsr_opt_v6 opt __align_stack_8 = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ret;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    ret = find_dsr_v6 (ctx, ip6 -> nexthdr, & opt, dsr);\n",
    "    if (ret != 0)\n",
    "        return ret;\n",
    "    if (*dsr) {\n",
    "        if (snat_v6_create_dsr (ctx, &opt.addr, opt.port) < 0)\n",
    "            return DROP_INVALID;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "snat_v6_create_dsr",
    "find_dsr_v6"
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
static __always_inline int handle_dsr_v6(struct __ctx_buff *ctx, bool *dsr)
{
	struct dsr_opt_v6 opt __align_stack_8 = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	ret = find_dsr_v6(ctx, ip6->nexthdr, &opt, dsr);
	if (ret != 0)
		return ret;

	if (*dsr) {
		if (snat_v6_create_dsr(ctx, &opt.addr, opt.port) < 0)
			return DROP_INVALID;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 402,
  "endLine": 418,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "xlate_dsr_v6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ipv6_ct_tuple *tuple",
    " int l4_off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int xlate_dsr_v6 (struct  __ctx_buff *ctx, const struct ipv6_ct_tuple *tuple, int l4_off)\n",
    "{\n",
    "    struct ipv6_ct_tuple nat_tup = *tuple;\n",
    "    struct ipv6_nat_entry *entry;\n",
    "    int ret = 0;\n",
    "    nat_tup.flags = NAT_DIR_EGRESS;\n",
    "    nat_tup.sport = tuple->dport;\n",
    "    nat_tup.dport = tuple->sport;\n",
    "    entry = snat_v6_lookup (& nat_tup);\n",
    "    if (entry)\n",
    "        ret = snat_v6_rewrite_egress (ctx, &nat_tup, entry, l4_off);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v6_rewrite_egress",
    "snat_v6_lookup"
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
static __always_inline int xlate_dsr_v6(struct __ctx_buff *ctx,
					const struct ipv6_ct_tuple *tuple,
					int l4_off)
{
	struct ipv6_ct_tuple nat_tup = *tuple;
	struct ipv6_nat_entry *entry;
	int ret = 0;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v6_lookup(&nat_tup);
	if (entry)
		ret = snat_v6_rewrite_egress(ctx, &nat_tup, entry, l4_off);
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 420,
  "endLine": 492,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_reply_icmp6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ipv6hdr * ip6 __maybe_unused",
    " int code",
    " int ohead __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_seg6local",
    "sched_act",
    "xdp",
    "lwt_xmit",
    "sched_cls",
    "lwt_in",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int dsr_reply_icmp6 (struct  __ctx_buff *ctx, const struct ipv6hdr * ip6 __maybe_unused, int code, int ohead __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_DSR_ICMP_ERRORS\n",
    "    const __s32 orig_dgram = 64, off = ETH_HLEN;\n",
    "    const __u32 l3_max = sizeof (*ip6) + orig_dgram;\n",
    "    __be16 type = bpf_htons (ETH_P_IPV6);\n",
    "    __u64 len_new = off + sizeof (*ip6) + orig_dgram;\n",
    "    __u64 len_old = ctx_full_len (ctx);\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    __u8 reason = (__u8) -code;\n",
    "    __wsum wsum;\n",
    "    union macaddr smac, dmac;\n",
    "    struct icmp6hdr icmp __align_stack_8 = {\n",
    "        .icmp6_type = ICMPV6_PKT_TOOBIG,\n",
    "        .icmp6_mtu = bpf_htonl (THIS_MTU - ohead),}\n",
    "    ;\n",
    "    __u64 payload_len = sizeof (*ip6) + sizeof (icmp) + orig_dgram;\n",
    "    struct ipv6hdr ip __align_stack_8 = {\n",
    "        .version = 6,\n",
    "        .priority = ip6->priority,\n",
    "        .flow_lbl [0] = ip6->flow_lbl[0],\n",
    "        .flow_lbl [1] = ip6->flow_lbl[1],\n",
    "        .flow_lbl [2] = ip6->flow_lbl[2],\n",
    "        .nexthdr = IPPROTO_ICMPV6,\n",
    "        .hop_limit = IPDEFTTL,\n",
    "        .saddr = ip6->daddr,\n",
    "        .daddr = ip6->saddr,\n",
    "        .payload_len = bpf_htons ((__u16) payload_len),}\n",
    "    ;\n",
    "    update_metrics (ctx_full_len (ctx), METRIC_EGRESS, reason);\n",
    "    if (eth_load_saddr (ctx, smac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_load_daddr (ctx, dmac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (unlikely (data + len_new > data_end))\n",
    "        goto drop_err;\n",
    "    wsum = ipv6_pseudohdr_checksum (& ip, IPPROTO_ICMPV6, bpf_ntohs (ip.payload_len), 0);\n",
    "    icmp.icmp6_cksum = csum_fold (csum_diff (NULL, 0, data + off, l3_max, csum_diff (NULL, 0, &icmp, sizeof (icmp), wsum)));\n",
    "    if (ctx_adjust_troom (ctx, -(len_old - len_new)) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (ip) + sizeof (icmp), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_store_daddr (ctx, smac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_store_saddr (ctx, dmac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, ETH_ALEN * 2, &type, sizeof (type), 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, off, &ip, sizeof (ip), 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, off + sizeof (ip), &icmp, sizeof (icmp), 0) < 0)\n",
    "        goto drop_err;\n",
    "    return ctx_redirect (ctx, ctx_get_ifindex (ctx), 0);\n",
    "drop_err :\n",
    "\n",
    "#endif\n",
    "    return send_drop_notify_error (ctx, 0, code, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_fold",
    "ctx_adjust_hroom_dsr_flags",
    "bpf_ntohs",
    "ctx_adjust_hroom",
    "eth_load_daddr",
    "unlikely",
    "ctx_redirect",
    "send_drop_notify_error",
    "update_metrics",
    "ctx_full_len",
    "bpf_htonl",
    "ctx_data_end",
    "eth_store_daddr",
    "ctx_store_bytes",
    "ctx_data",
    "eth_load_saddr",
    "ctx_adjust_troom",
    "ctx_get_ifindex",
    "ipv6_pseudohdr_checksum",
    "eth_store_saddr",
    "bpf_htons"
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
static __always_inline int dsr_reply_icmp6(struct __ctx_buff *ctx,
					   const struct ipv6hdr *ip6 __maybe_unused,
					   int code, int ohead __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	const __s32 orig_dgram = 64, off = ETH_HLEN;
	const __u32 l3_max = sizeof(*ip6) + orig_dgram;
	__be16 type = bpf_htons(ETH_P_IPV6);
	__u64 len_new = off + sizeof(*ip6) + orig_dgram;
	__u64 len_old = ctx_full_len(ctx);
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	__u8 reason = (__u8)-code;
	__wsum wsum;
	union macaddr smac, dmac;
	struct icmp6hdr icmp __align_stack_8 = {
		.icmp6_type	= ICMPV6_PKT_TOOBIG,
		.icmp6_mtu	= bpf_htonl(THIS_MTU - ohead),
	};
	__u64 payload_len = sizeof(*ip6) + sizeof(icmp) + orig_dgram;
	struct ipv6hdr ip __align_stack_8 = {
		.version	= 6,
		.priority	= ip6->priority,
		.flow_lbl[0]	= ip6->flow_lbl[0],
		.flow_lbl[1]	= ip6->flow_lbl[1],
		.flow_lbl[2]	= ip6->flow_lbl[2],
		.nexthdr	= IPPROTO_ICMPV6,
		.hop_limit	= IPDEFTTL,
		.saddr		= ip6->daddr,
		.daddr		= ip6->saddr,
		.payload_len	= bpf_htons((__u16)payload_len),
	};

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, reason);

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (unlikely(data + len_new > data_end))
		goto drop_err;

	wsum = ipv6_pseudohdr_checksum(&ip, IPPROTO_ICMPV6,
				       bpf_ntohs(ip.payload_len), 0);
	icmp.icmp6_cksum = csum_fold(csum_diff(NULL, 0, data + off, l3_max,
					       csum_diff(NULL, 0, &icmp,
							 sizeof(icmp), wsum)));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()) < 0)
		goto drop_err;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_store_saddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, ETH_ALEN * 2, &type, sizeof(type), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off, &ip, sizeof(ip), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip), &icmp,
			    sizeof(icmp), 0) < 0)
		goto drop_err;

	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
drop_err:
#endif
	return send_drop_notify_error(ctx, 0, code, CTX_ACT_DROP,
				      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_DSR)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 495,
  "endLine": 571,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_nodeport_ipv6_dsr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "fib_lookup",
    "bpf_fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_nodeport_ipv6_dsr (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct bpf_fib_lookup_padded fib_params = {\n",
    "        .l = {\n",
    "            .family = AF_INET6,\n",
    "            .ifindex = ctx_get_ifindex (ctx),},}\n",
    "    ;\n",
    "    __u16 port __maybe_unused;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    union v6addr addr;\n",
    "    int ret, ohead = 0;\n",
    "    int ext_err = 0;\n",
    "    bool l2_hdr_required = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    addr.p1 = ctx_load_meta (ctx, CB_ADDR_V6_1);\n",
    "    addr.p2 = ctx_load_meta (ctx, CB_ADDR_V6_2);\n",
    "    addr.p3 = ctx_load_meta (ctx, CB_ADDR_V6_3);\n",
    "    addr.p4 = ctx_load_meta (ctx, CB_ADDR_V6_4);\n",
    "\n",
    "#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "    ret = dsr_set_ipip6 (ctx, ip6, & addr, ctx_load_meta (ctx, CB_HINT), & ohead);\n",
    "\n",
    "#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE\n",
    "    port = (__u16) ctx_load_meta (ctx, CB_PORT);\n",
    "    ret = dsr_set_ext6 (ctx, ip6, & addr, port, & ohead);\n",
    "\n",
    "#else\n",
    "\n",
    "# error \"Invalid load balancer DSR encapsulation mode!\"\n",
    "\n",
    "#endif\n",
    "    if (unlikely (ret)) {\n",
    "        if (dsr_fail_needs_reply (ret))\n",
    "            return dsr_reply_icmp6 (ctx, ip6, ret, ohead);\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    ipv6_addr_copy ((union v6addr *) &fib_params.l.ipv6_src, (union v6addr *) &ip6->saddr);\n",
    "    ipv6_addr_copy ((union v6addr *) &fib_params.l.ipv6_dst, (union v6addr *) &ip6->daddr);\n",
    "    ret = fib_lookup (ctx, & fib_params.l, sizeof (fib_params), 0);\n",
    "    if (ret != 0) {\n",
    "        ext_err = ret;\n",
    "        ret = DROP_NO_FIB;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    ret = maybe_add_l2_hdr (ctx, fib_params.l.ifindex, & l2_hdr_required);\n",
    "    if (ret != 0)\n",
    "        goto drop_err;\n",
    "    if (!l2_hdr_required)\n",
    "        goto out_send;\n",
    "    if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "out_send :\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, fib_params.l.ifindex, 0);\n",
    "drop_err :\n",
    "    return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "dsr_reply_icmp6",
    "revalidate_data",
    "maybe_add_l2_hdr",
    "cilium_capture_out",
    "dsr_set_ipip6",
    "ctx_load_meta",
    "eth_store_daddr",
    "ctx_get_ifindex",
    "unlikely",
    "ctx_redirect",
    "dsr_fail_needs_reply",
    "dsr_set_ext6",
    "eth_store_saddr",
    "ipv6_addr_copy",
    "send_drop_notify_error_ext"
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
int tail_nodeport_ipv6_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	__u16 port __maybe_unused;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr addr;
	int ret, ohead = 0;
	int ext_err = 0;
	bool l2_hdr_required = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	addr.p1 = ctx_load_meta(ctx, CB_ADDR_V6_1);
	addr.p2 = ctx_load_meta(ctx, CB_ADDR_V6_2);
	addr.p3 = ctx_load_meta(ctx, CB_ADDR_V6_3);
	addr.p4 = ctx_load_meta(ctx, CB_ADDR_V6_4);

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip6(ctx, ip6, &addr,
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	port = (__u16)ctx_load_meta(ctx, CB_PORT);
	ret = dsr_set_ext6(ctx, ip6, &addr, port, &ohead);
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (unlikely(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp6(ctx, ip6, ret, ohead);
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ext_err = ret;
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_NAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 575,
  "endLine": 715,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_nodeport_nat_ipv6",
  "developer_inline_comments": [
    {
      "start_line": 623,
      "end_line": 623,
      "text": "/* fib lookup not necessary when going over tunnel. */"
    },
    {
      "start_line": 637,
      "end_line": 641,
      "text": "/* In case of no mapping, recircle back to main path. SNAT is very\n\t\t * expensive in terms of instructions (since we don't have BPF to\n\t\t * BPF calls as we use tail calls) and complexity, hence this is\n\t\t * done inside a tail call here.\n\t\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "fib_lookup",
    "bpf_fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_nodeport_nat_ipv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    enum nat_dir dir = (enum nat_dir) ctx_load_meta (ctx, CB_NAT);\n",
    "    const bool nat_46x64 = ctx_load_meta (ctx, CB_NAT_46X64);\n",
    "    union v6addr tmp = IPV6_DIRECT_ROUTING;\n",
    "    struct bpf_fib_lookup_padded fib_params = {\n",
    "        .l = {\n",
    "            .family = AF_INET6,\n",
    "            .ifindex = ctx_get_ifindex (ctx),},}\n",
    "    ;\n",
    "    struct ipv6_nat_target target = {\n",
    "        .min_port = NODEPORT_PORT_MIN_NAT,\n",
    "        .max_port = NODEPORT_PORT_MAX_NAT,\n",
    "        .src_from_world = true,}\n",
    "    ;\n",
    "    bool l2_hdr_required = true;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ret, ext_err = 0;\n",
    "    if (nat_46x64)\n",
    "        build_v4_in_v6 (&tmp, IPV4_DIRECT_ROUTING);\n",
    "    target.addr = tmp;\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    if (dir == NAT_DIR_EGRESS) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        union v6addr *dst;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "            ret = DROP_INVALID;\n",
    "            goto drop_err;\n",
    "        }\n",
    "        dst = (union v6addr *) &ip6->daddr;\n",
    "        info = ipcache_lookup6 (& IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);\n",
    "        if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "            ret = __encap_with_nodeid (ctx, info -> tunnel_endpoint, WORLD_ID, NOT_VTEP_DST, (enum trace_reason) CT_NEW, TRACE_PAYLOAD_LEN);\n",
    "            if (ret)\n",
    "                goto drop_err;\n",
    "            BPF_V6 (target.addr, ROUTER_IP);\n",
    "            fib_params.l.ifindex = ENCAP_IFINDEX;\n",
    "            if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "                ret = DROP_WRITE_ERROR;\n",
    "                goto drop_err;\n",
    "            }\n",
    "            if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "                ret = DROP_WRITE_ERROR;\n",
    "                goto drop_err;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    ret = snat_v6_process (ctx, dir, & target);\n",
    "    if (IS_ERR (ret)) {\n",
    "        if (dir == NAT_DIR_INGRESS) {\n",
    "            bpf_skip_nodeport_set (ctx);\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "            ret = DROP_MISSED_TAIL_CALL;\n",
    "            goto drop_err;\n",
    "        }\n",
    "        if (ret != NAT_PUNT_TO_STACK)\n",
    "            goto drop_err;\n",
    "    }\n",
    "    bpf_mark_snat_done (ctx);\n",
    "    if (dir == NAT_DIR_INGRESS) {\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        goto drop_err;\n",
    "    }\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    if (fib_params.l.ifindex == ENCAP_IFINDEX)\n",
    "        goto out_send;\n",
    "\n",
    "#endif\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (nat_46x64) {\n",
    "        struct iphdr *ip4;\n",
    "        ret = lb6_to_lb4 (ctx, ip6);\n",
    "        if (ret < 0)\n",
    "            goto drop_err;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "            ret = DROP_INVALID;\n",
    "            goto drop_err;\n",
    "        }\n",
    "        fib_params.l.ipv4_src = ip4->saddr;\n",
    "        fib_params.l.ipv4_dst = ip4->daddr;\n",
    "        fib_params.l.family = AF_INET;\n",
    "    }\n",
    "    else {\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.l.ipv6_src, (union v6addr *) &ip6->saddr);\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.l.ipv6_dst, (union v6addr *) &ip6->daddr);\n",
    "    }\n",
    "    ret = fib_lookup (ctx, & fib_params.l, sizeof (fib_params), 0);\n",
    "    if (ret != 0) {\n",
    "        ext_err = ret;\n",
    "        ret = DROP_NO_FIB;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    ret = maybe_add_l2_hdr (ctx, fib_params.l.ifindex, & l2_hdr_required);\n",
    "    if (ret != 0)\n",
    "        goto drop_err;\n",
    "    if (!l2_hdr_required)\n",
    "        goto out_send;\n",
    "    if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "out_send :\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, fib_params.l.ifindex, 0);\n",
    "drop_err :\n",
    "    return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, dir == NAT_DIR_INGRESS ? METRIC_INGRESS : METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_skip_nodeport_set",
    "ipcache_lookup6",
    "cilium_capture_out",
    "send_drop_notify_error_ext",
    "ctx_redirect",
    "ipv6_addr_copy",
    "maybe_add_l2_hdr",
    "ep_tail_call",
    "eth_store_daddr",
    "build_v4_in_v6",
    "lb6_to_lb4",
    "revalidate_data",
    "bpf_mark_snat_done",
    "__encap_with_nodeid",
    "snat_v6_process",
    "ctx_get_ifindex",
    "BPF_V6",
    "IS_ERR",
    "ctx_load_meta",
    "eth_store_saddr"
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
int tail_nodeport_nat_ipv6(struct __ctx_buff *ctx)
{
	enum nat_dir dir = (enum nat_dir)ctx_load_meta(ctx, CB_NAT);
	const bool nat_46x64 = ctx_load_meta(ctx, CB_NAT_46X64);
	union v6addr tmp = IPV6_DIRECT_ROUTING;
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET6,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	struct ipv6_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	bool l2_hdr_required = true;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, ext_err = 0;

	if (nat_46x64)
		build_v4_in_v6(&tmp, IPV4_DIRECT_ROUTING);
	target.addr = tmp;
#ifdef TUNNEL_MODE
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;
		union v6addr *dst;

		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		dst = (union v6addr *)&ip6->daddr;
		info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  WORLD_ID,
						  NOT_VTEP_DST,
						  (enum trace_reason)CT_NEW,
						  TRACE_PAYLOAD_LEN);
			if (ret)
				goto drop_err;

			BPF_V6(target.addr, ROUTER_IP);
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
		}
	}
#endif
	ret = snat_v6_process(ctx, dir, &target);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
			ret = DROP_MISSED_TAIL_CALL;
			goto drop_err;
		}
		if (ret != NAT_PUNT_TO_STACK)
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef TUNNEL_MODE
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto drop_err;
	}
	if (nat_46x64) {
		struct iphdr *ip4;

		ret = lb6_to_lb4(ctx, ip6);
		if (ret < 0)
			goto drop_err;
		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}
		fib_params.l.ipv4_src = ip4->saddr;
		fib_params.l.ipv4_dst = ip4->daddr;
		fib_params.l.family = AF_INET;
	} else {
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_src,
			       (union v6addr *)&ip6->saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.l.ipv6_dst,
			       (union v6addr *)&ip6->daddr);
	}

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ext_err = ret;
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* See nodeport_lb4(). */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_update"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 718,
  "endLine": 881,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_lb6",
  "developer_inline_comments": [
    {
      "start_line": 717,
      "end_line": 717,
      "text": "/* See nodeport_lb4(). */"
    },
    {
      "start_line": 859,
      "end_line": 859,
      "text": "/* DSR_ENCAP_MODE */"
    },
    {
      "start_line": 863,
      "end_line": 869,
      "text": "/* This code path is not only hit for NAT64, but also\n\t\t\t * for NAT46. For the latter we initially hit the IPv4\n\t\t\t * NodePort path, then migrate the request to IPv6 and\n\t\t\t * recirculate into the regular IPv6 NodePort path. So\n\t\t\t * we need to make sure to not NAT back to IPv4 for\n\t\t\t * IPv4-in-IPv6 converted addresses.\n\t\t\t */"
    }
  ],
  "updateMaps": [
    "  NODEPORT_NEIGH6"
  ],
  "readMaps": [
    "  NODEPORT_NEIGH6"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 src_identity"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "map_update_elem",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int nodeport_lb6 (struct  __ctx_buff *ctx, __u32 src_identity)\n",
    "{\n",
    "    int ret, l3_off = ETH_HLEN, l4_off, hdrlen;\n",
    "    struct ipv6_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    struct csum_offset csum_off = {}\n",
    "    ;\n",
    "    struct lb6_service *svc;\n",
    "    struct lb6_key key = {}\n",
    "    ;\n",
    "    struct ct_state ct_state_new = {}\n",
    "    ;\n",
    "    union macaddr smac, *mac;\n",
    "    bool backend_local;\n",
    "    __u32 monitor = 0;\n",
    "    cilium_capture_in (ctx);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip6->nexthdr;\n",
    "    ipv6_addr_copy (&tuple.daddr, (union v6addr *) &ip6->daddr);\n",
    "    ipv6_addr_copy (&tuple.saddr, (union v6addr *) &ip6->saddr);\n",
    "    hdrlen = ipv6_hdrlen (ctx, & tuple.nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    l4_off = l3_off + hdrlen;\n",
    "    ret = lb6_extract_key (ctx, & tuple, l4_off, & key, & csum_off, CT_EGRESS);\n",
    "    if (IS_ERR (ret)) {\n",
    "        if (ret == DROP_NO_SERVICE)\n",
    "            goto skip_service_lookup;\n",
    "        else if (ret == DROP_UNKNOWN_L4)\n",
    "            return CTX_ACT_OK;\n",
    "        else\n",
    "            return ret;\n",
    "    }\n",
    "    svc = lb6_lookup_service (& key, false);\n",
    "    if (svc) {\n",
    "        const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;\n",
    "        if (!lb6_src_range_ok (svc, (union v6addr *) &ip6->saddr))\n",
    "            return DROP_NOT_IN_SRC_RANGE;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "        if (lb6_svc_is_l7loadbalancer (svc) && svc->l7_lb_proxy_port > 0) {\n",
    "            send_trace_notify (ctx, TRACE_TO_PROXY, src_identity, 0, bpf_ntohs ((__u16) svc->l7_lb_proxy_port), 0, TRACE_REASON_POLICY, monitor);\n",
    "            return ctx_redirect_to_proxy_hairpin_ipv6 (ctx, (__be16) svc->l7_lb_proxy_port);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        ret = lb6_local (get_ct_map6 (& tuple), ctx, l3_off, l4_off, & csum_off, & key, & tuple, svc, & ct_state_new, skip_l3_xlate);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (!svc || !lb6_svc_is_routable (svc)) {\n",
    "        if (svc)\n",
    "            return DROP_IS_CLUSTER_IP;\n",
    "    skip_service_lookup :\n",
    "        ctx_set_xfer (ctx, XFER_PKT_NO_SVC);\n",
    "        if (nodeport_uses_dsr6 (&tuple))\n",
    "            return CTX_ACT_OK;\n",
    "        ctx_store_meta (ctx, CB_NAT, NAT_DIR_INGRESS);\n",
    "        ctx_store_meta (ctx, CB_NAT_46X64, 0);\n",
    "        ctx_store_meta (ctx, CB_SRC_IDENTITY, src_identity);\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "    backend_local = __lookup_ip6_endpoint (& tuple.daddr);\n",
    "    if (!backend_local && lb6_svc_is_hostport (svc))\n",
    "        return DROP_INVALID;\n",
    "    if (backend_local || !nodeport_uses_dsr6 (&tuple)) {\n",
    "        struct ct_state ct_state = {}\n",
    "        ;\n",
    "        ret = ct_lookup6 (get_ct_map6 (& tuple), & tuple, ctx, l4_off, CT_EGRESS, & ct_state, & monitor);\n",
    "        switch (ret) {\n",
    "        case CT_NEW :\n",
    "        redo :\n",
    "            ct_state_new.src_sec_id = WORLD_ID;\n",
    "            ct_state_new.node_port = 1;\n",
    "            ct_state_new.ifindex = (__u16) NATIVE_DEV_IFINDEX;\n",
    "            ret = ct_create6 (get_ct_map6 (& tuple), NULL, & tuple, ctx, CT_EGRESS, & ct_state_new, false, false);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "            break;\n",
    "        case CT_REOPENED :\n",
    "        case CT_ESTABLISHED :\n",
    "        case CT_REPLY :\n",
    "            if (unlikely (ct_state.rev_nat_index != svc->rev_nat_index))\n",
    "                goto redo;\n",
    "            break;\n",
    "        default :\n",
    "            return DROP_UNKNOWN_CT;\n",
    "        }\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "        if (eth_load_saddr (ctx, smac.addr, 0) < 0)\n",
    "            return DROP_INVALID;\n",
    "        mac = map_lookup_elem (& NODEPORT_NEIGH6, & ip6 -> saddr);\n",
    "        if (!mac || eth_addrcmp (mac, &smac)) {\n",
    "            ret = map_update_elem (& NODEPORT_NEIGH6, & ip6 -> saddr, & smac, 0);\n",
    "            if (ret < 0)\n",
    "                return ret;\n",
    "        }\n",
    "    }\n",
    "    if (!backend_local) {\n",
    "        edt_set_aggregate (ctx, 0);\n",
    "        if (nodeport_uses_dsr6 (&tuple)) {\n",
    "\n",
    "#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "            ctx_store_meta (ctx, CB_HINT, ((__u32) tuple.sport << 16) | tuple.dport);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_1, tuple.daddr.p1);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_2, tuple.daddr.p2);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_3, tuple.daddr.p3);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_4, tuple.daddr.p4);\n",
    "\n",
    "#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE\n",
    "            ctx_store_meta (ctx, CB_PORT, key.dport);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_1, key.address.p1);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_2, key.address.p2);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_3, key.address.p3);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V6_4, key.address.p4);\n",
    "\n",
    "#endif /* DSR_ENCAP_MODE */\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_DSR);\n",
    "        }\n",
    "        else {\n",
    "            ctx_store_meta (ctx, CB_NAT, NAT_DIR_EGRESS);\n",
    "            ctx_store_meta (ctx, CB_NAT_46X64, !is_v4_in_v6 (&key.address) && lb6_to_lb4_service (svc));\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);\n",
    "        }\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "    ctx_set_xfer (ctx, XFER_PKT_NO_SVC);\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "nodeport_uses_dsr6",
    "ctx_set_xfer",
    "bpf_ntohs",
    "lb6_svc_is_hostport",
    "cilium_capture_in",
    "is_v4_in_v6",
    "ctx_store_meta",
    "lb6_extract_key",
    "lb6_lookup_service",
    "unlikely",
    "__lookup_ip6_endpoint",
    "eth_addrcmp",
    "ipv6_addr_copy",
    "lb6_src_range_ok",
    "ct_lookup6",
    "ipv6_hdrlen",
    "edt_set_aggregate",
    "ctx_redirect_to_proxy_hairpin_ipv6",
    "lb6_svc_is_routable",
    "ep_tail_call",
    "send_trace_notify",
    "lb6_svc_is_l7loadbalancer",
    "ct_create6",
    "get_ct_map6",
    "revalidate_data",
    "eth_load_saddr",
    "lb6_local",
    "lb6_to_lb4_service",
    "defined",
    "IS_ERR"
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
static __always_inline int nodeport_lb6(struct __ctx_buff *ctx,
					__u32 src_identity)
{
	int ret, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct lb6_service *svc;
	struct lb6_key key = {};
	struct ct_state ct_state_new = {};
	union macaddr smac, *mac;
	bool backend_local;
	__u32 monitor = 0;

	cilium_capture_in(ctx);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;

	ret = lb6_extract_key(ctx, &tuple, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE)
			goto skip_service_lookup;
		else if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	svc = lb6_lookup_service(&key, false);
	if (svc) {
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
			return DROP_NOT_IN_SRC_RANGE;

#if defined(ENABLE_L7_LB)
		if (lb6_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
			send_trace_notify(ctx, TRACE_TO_PROXY, src_identity, 0,
					  bpf_ntohs((__u16)svc->l7_lb_proxy_port), 0,
					  TRACE_REASON_POLICY, monitor);
			return ctx_redirect_to_proxy_hairpin_ipv6(ctx,
								  (__be16)svc->l7_lb_proxy_port);
		}
#endif
		ret = lb6_local(get_ct_map6(&tuple), ctx, l3_off, l4_off,
				&csum_off, &key, &tuple, svc, &ct_state_new,
				skip_l3_xlate);
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || !lb6_svc_is_routable(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

skip_service_lookup:
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

		if (nodeport_uses_dsr6(&tuple))
			return CTX_ACT_OK;

		ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
		ctx_store_meta(ctx, CB_NAT_46X64, 0);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
		ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip6_endpoint(&tuple.daddr);
	if (!backend_local && lb6_svc_is_hostport(svc))
		return DROP_INVALID;

	if (backend_local || !nodeport_uses_dsr6(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off,
				 CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_NEW:
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create6(get_ct_map6(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo;
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
		if (eth_load_saddr(ctx, smac.addr, 0) < 0)
			return DROP_INVALID;

		mac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->saddr);
		if (!mac || eth_addrcmp(mac, &smac)) {
			ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr,
					      &smac, 0);
			if (ret < 0)
				return ret;
		}
	}

	if (!backend_local) {
		edt_set_aggregate(ctx, 0);
		if (nodeport_uses_dsr6(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
			ctx_store_meta(ctx, CB_HINT,
				       ((__u32)tuple.sport << 16) | tuple.dport);
			ctx_store_meta(ctx, CB_ADDR_V6_1, tuple.daddr.p1);
			ctx_store_meta(ctx, CB_ADDR_V6_2, tuple.daddr.p2);
			ctx_store_meta(ctx, CB_ADDR_V6_3, tuple.daddr.p3);
			ctx_store_meta(ctx, CB_ADDR_V6_4, tuple.daddr.p4);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
			ctx_store_meta(ctx, CB_PORT, key.dport);
			ctx_store_meta(ctx, CB_ADDR_V6_1, key.address.p1);
			ctx_store_meta(ctx, CB_ADDR_V6_2, key.address.p2);
			ctx_store_meta(ctx, CB_ADDR_V6_3, key.address.p3);
			ctx_store_meta(ctx, CB_ADDR_V6_4, key.address.p4);
#endif /* DSR_ENCAP_MODE */
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			/* This code path is not only hit for NAT64, but also
			 * for NAT46. For the latter we initially hit the IPv4
			 * NodePort path, then migrate the request to IPv6 and
			 * recirculate into the regular IPv6 NodePort path. So
			 * we need to make sure to not NAT back to IPv4 for
			 * IPv4-in-IPv6 converted addresses.
			 */
			ctx_store_meta(ctx, CB_NAT_46X64,
				       !is_v4_in_v6(&key.address) &&
				       lb6_to_lb4_service(svc));
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

	return CTX_ACT_OK;
}

/* See comment in tail_rev_nodeport_lb4(). */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 884,
  "endLine": 1006,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "rev_nodeport_lb6",
  "developer_inline_comments": [
    {
      "start_line": 883,
      "end_line": 883,
      "text": "/* See comment in tail_rev_nodeport_lb4(). */"
    },
    {
      "start_line": 943,
      "end_line": 943,
      "text": "/* fib lookup not necessary when going over tunnel. */"
    },
    {
      "start_line": 981,
      "end_line": 981,
      "text": "/* See comment in rev_nodeport_lb4(). */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  NODEPORT_NEIGH6"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int *ifindex",
    " int *ext_err"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "fib_lookup",
    "CTX_ACT_OK",
    "bpf_fib_lookup",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int rev_nodeport_lb6 (struct  __ctx_buff *ctx, int *ifindex, int *ext_err)\n",
    "{\n",
    "    int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;\n",
    "    struct ipv6_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    struct csum_offset csum_off = {}\n",
    "    ;\n",
    "    struct ct_state ct_state = {}\n",
    "    ;\n",
    "    struct bpf_fib_lookup fib_params = {}\n",
    "    ;\n",
    "    __u32 monitor = 0;\n",
    "    bool l2_hdr_required = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip6->nexthdr;\n",
    "    ipv6_addr_copy (&tuple.daddr, (union v6addr *) &ip6->daddr);\n",
    "    ipv6_addr_copy (&tuple.saddr, (union v6addr *) &ip6->saddr);\n",
    "    hdrlen = ipv6_hdrlen (ctx, & tuple.nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    l4_off = l3_off + hdrlen;\n",
    "    csum_l4_offset_and_flags (tuple.nexthdr, &csum_off);\n",
    "    ret = ct_lookup6 (get_ct_map6 (& tuple), & tuple, ctx, l4_off, CT_INGRESS, & ct_state, & monitor);\n",
    "    if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {\n",
    "        ret2 = lb6_rev_nat (ctx, l4_off, & csum_off, ct_state.rev_nat_index, & tuple, REV_NAT_F_TUPLE_SADDR);\n",
    "        if (IS_ERR (ret2))\n",
    "            return ret2;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "        bpf_mark_snat_done (ctx);\n",
    "        *ifindex = ct_state.ifindex;\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "        {\n",
    "            union v6addr *dst = (union v6addr *) &ip6->daddr;\n",
    "            struct remote_endpoint_info *info;\n",
    "            info = ipcache_lookup6 (& IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);\n",
    "            if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "                ret = __encap_with_nodeid (ctx, info -> tunnel_endpoint, SECLABEL, NOT_VTEP_DST, TRACE_REASON_CT_REPLY, TRACE_PAYLOAD_LEN);\n",
    "                if (ret)\n",
    "                    return ret;\n",
    "                *ifindex = ENCAP_IFINDEX;\n",
    "                if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "                    return DROP_WRITE_ERROR;\n",
    "                if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "                    return DROP_WRITE_ERROR;\n",
    "                return CTX_ACT_OK;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        fib_params.family = AF_INET6;\n",
    "        fib_params.ifindex = ctx_get_ifindex (ctx);\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_src, &tuple.saddr);\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_dst, &tuple.daddr);\n",
    "        fib_ret = fib_lookup (ctx, & fib_params, sizeof (fib_params), 0);\n",
    "        if (fib_ret == 0)\n",
    "            *ifindex = fib_params.ifindex;\n",
    "        ret = maybe_add_l2_hdr (ctx, * ifindex, & l2_hdr_required);\n",
    "        if (ret != 0)\n",
    "            return ret;\n",
    "        if (!l2_hdr_required)\n",
    "            return CTX_ACT_OK;\n",
    "        if (fib_ret != 0) {\n",
    "            union macaddr smac = NATIVE_DEV_MAC_BY_IFINDEX (* ifindex);\n",
    "            union macaddr *dmac;\n",
    "            if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH) {\n",
    "                *ext_err = fib_ret;\n",
    "                return DROP_NO_FIB;\n",
    "            }\n",
    "            dmac = map_lookup_elem (& NODEPORT_NEIGH6, & tuple.daddr);\n",
    "            if (unlikely (!dmac)) {\n",
    "                *ext_err = fib_ret;\n",
    "                return DROP_NO_FIB;\n",
    "            }\n",
    "            if (eth_store_daddr_aligned (ctx, dmac->addr, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "            if (eth_store_saddr_aligned (ctx, smac.addr, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "        }\n",
    "        else {\n",
    "            if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "            if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if (!bpf_skip_recirculation (ctx)) {\n",
    "            bpf_skip_nodeport_set (ctx);\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_skip_nodeport_set",
    "ipcache_lookup6",
    "NATIVE_DEV_MAC_BY_IFINDEX",
    "unlikely",
    "lb6_rev_nat",
    "ipv6_addr_copy",
    "ct_lookup6",
    "ipv6_hdrlen",
    "maybe_add_l2_hdr",
    "ep_tail_call",
    "eth_store_daddr",
    "eth_store_saddr_aligned",
    "get_ct_map6",
    "revalidate_data",
    "bpf_mark_snat_done",
    "__encap_with_nodeid",
    "ctx_get_ifindex",
    "IS_ERR",
    "bpf_skip_recirculation",
    "eth_store_daddr_aligned",
    "eth_store_saddr",
    "csum_l4_offset_and_flags"
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
static __always_inline int rev_nodeport_lb6(struct __ctx_buff *ctx, int *ifindex,
					    int *ext_err)
{
	int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off, hdrlen;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct csum_offset csum_off = {};
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	__u32 monitor = 0;
	bool l2_hdr_required = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *) &ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *) &ip6->saddr);

	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	l4_off = l3_off + hdrlen;
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

	ret = ct_lookup6(get_ct_map6(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		ret2 = lb6_rev_nat(ctx, l4_off, &csum_off, ct_state.rev_nat_index,
				   &tuple, REV_NAT_F_TUPLE_SADDR);
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);

		*ifindex = ct_state.ifindex;
#ifdef TUNNEL_MODE
		{
			union v6addr *dst = (union v6addr *)&ip6->daddr;
			struct remote_endpoint_info *info;

			info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
							  SECLABEL,
							  NOT_VTEP_DST,
							  TRACE_REASON_CT_REPLY,
							  TRACE_PAYLOAD_LEN);
				if (ret)
					return ret;

				*ifindex = ENCAP_IFINDEX;

				/* fib lookup not necessary when going over tunnel. */
				if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
					return DROP_WRITE_ERROR;
				if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
					return DROP_WRITE_ERROR;

				return CTX_ACT_OK;
			}
		}
#endif

		fib_params.family = AF_INET6;
		fib_params.ifindex = ctx_get_ifindex(ctx);

		ipv6_addr_copy((union v6addr *)&fib_params.ipv6_src, &tuple.saddr);
		ipv6_addr_copy((union v6addr *)&fib_params.ipv6_dst, &tuple.daddr);

		fib_ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

		if (fib_ret == 0)
			*ifindex = fib_params.ifindex;

		ret = maybe_add_l2_hdr(ctx, *ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			return CTX_ACT_OK;

		if (fib_ret != 0) {
			union macaddr smac =
				NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);
			union macaddr *dmac;

			if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH) {
				*ext_err = fib_ret;
				return DROP_NO_FIB;
			}

			/* See comment in rev_nodeport_lb4(). */
			dmac = map_lookup_elem(&NODEPORT_NEIGH6, &tuple.daddr);
			if (unlikely(!dmac)) {
				*ext_err = fib_ret;
				return DROP_NO_FIB;
			}
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_NODEPORT_REVNAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1009,
  "endLine": 1052,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_rev_nodeport_lb6",
  "developer_inline_comments": [
    {
      "start_line": 1017,
      "end_line": 1019,
      "text": "/* We only enforce the host policies if nodeport.h is included from\n\t * bpf_host.\n\t */"
    },
    {
      "start_line": 1030,
      "end_line": 1032,
      "text": "/* We don't want to enforce host policies a second time if we jump back to\n\t * bpf_host's handle_ipv6.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_rev_nodeport_lb6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ifindex = 0, ret = 0;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ext_err = 0;\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u32 src_id = 0;\n",
    "    ret = ipv6_host_policy_ingress (ctx, & src_id, & trace);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    ctx_skip_host_fw_set (ctx);\n",
    "\n",
    "#endif\n",
    "    ret = rev_nodeport_lb6 (ctx, & ifindex, & ext_err);\n",
    "    if (IS_ERR (ret))\n",
    "        goto drop;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        goto drop;\n",
    "    if (is_v4_in_v6 ((union v6addr *) &ip6->saddr)) {\n",
    "        ret = lb6_to_lb4 (ctx, ip6);\n",
    "        if (ret)\n",
    "            goto drop;\n",
    "    }\n",
    "    edt_set_aggregate (ctx, 0);\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, ifindex, 0);\n",
    "drop :\n",
    "    return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "is_v4_in_v6",
    "revalidate_data",
    "edt_set_aggregate",
    "send_drop_notify_error_ext",
    "cilium_capture_out",
    "defined",
    "IS_ERR",
    "ctx_redirect",
    "ctx_skip_host_fw_set",
    "send_drop_notify_error",
    "lb6_to_lb4",
    "rev_nodeport_lb6",
    "ipv6_host_policy_ingress"
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
int tail_rev_nodeport_lb6(struct __ctx_buff *ctx)
{
	int ifindex = 0, ret = 0;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ext_err = 0;

#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)
	/* We only enforce the host policies if nodeport.h is included from
	 * bpf_host.
	 */
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb6(ctx, &ifindex, &ext_err);
	if (IS_ERR(ret))
		goto drop;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		goto drop;
	if (is_v4_in_v6((union v6addr *)&ip6->saddr)) {
		ret = lb6_to_lb4(ctx, ip6);
		if (ret)
			goto drop;
	}

	edt_set_aggregate(ctx, 0);
	cilium_capture_out(ctx);

	return ctx_redirect(ctx, ifindex, 0);
drop:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);
}

declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
			       is_defined(ENABLE_IPV6)),
			 __and(is_defined(ENABLE_HOST_FIREWALL),
			       is_defined(IS_BPF_HOST))),
		    CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1059,
  "endLine": 1078,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_handle_nat_fwd_ipv6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_handle_nat_fwd_ipv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret;\n",
    "    enum trace_point obs_point;\n",
    "\n",
    "#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)\n",
    "    union v6addr addr = {\n",
    "        .p1 = 0}\n",
    "    ;\n",
    "    BPF_V6 (addr, ROUTER_IP);\n",
    "    obs_point = TRACE_TO_OVERLAY;\n",
    "\n",
    "#else\n",
    "    union v6addr addr = IPV6_DIRECT_ROUTING;\n",
    "    obs_point = TRACE_TO_NETWORK;\n",
    "\n",
    "#endif\n",
    "    ret = nodeport_nat_ipv6_fwd (ctx, & addr);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "    send_trace_notify (ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "nodeport_nat_ipv6_fwd",
    "send_trace_notify",
    "BPF_V6",
    "IS_ERR",
    "send_drop_notify_error"
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
int tail_handle_nat_fwd_ipv6(struct __ctx_buff *ctx)
{
	int ret;
	enum trace_point obs_point;
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	union v6addr addr = { .p1 = 0 };
	BPF_V6(addr, ROUTER_IP);
	obs_point = TRACE_TO_OVERLAY;
#else
	union v6addr addr = IPV6_DIRECT_ROUTING;
	obs_point = TRACE_TO_NETWORK;
#endif
	ret = nodeport_nat_ipv6_fwd(ctx, &addr);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1082,
  "endLine": 1085,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_uses_dsr4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *tuple"
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
    "static __always_inline bool nodeport_uses_dsr4 (const struct ipv4_ct_tuple *tuple)\n",
    "{\n",
    "    return nodeport_uses_dsr (tuple->nexthdr);\n",
    "}\n"
  ],
  "called_function_list": [
    "nodeport_uses_dsr"
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
static __always_inline bool nodeport_uses_dsr4(const struct ipv4_ct_tuple *tuple)
{
	return nodeport_uses_dsr(tuple->nexthdr);
}

/* The function contains a core logic for deciding whether an egressing packet
 * has to be SNAT-ed. Currently, the function targets the following flows:
 *
 *	- From pod to outside to masquerade requests
 *	  when --enable-bpf-masquerade=true.
 *	- From host to outside to track (and masquerade) flows which
 *	  can conflict with NodePort BPF.
 *
 * The function sets "addr" to the SNAT IP addr, and "from_endpoint" to true
 * if the packet is sent from a local endpoint.
 *
 * Callers should treat contents of "from_endpoint" and "addr" as undetermined,
 * if function returns false.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1101,
  "endLine": 1259,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "snat_v4_needed",
  "developer_inline_comments": [
    {
      "start_line": 1087,
      "end_line": 1100,
      "text": "/* The function contains a core logic for deciding whether an egressing packet\n * has to be SNAT-ed. Currently, the function targets the following flows:\n *\n *\t- From pod to outside to masquerade requests\n *\t  when --enable-bpf-masquerade=true.\n *\t- From host to outside to track (and masquerade) flows which\n *\t  can conflict with NodePort BPF.\n *\n * The function sets \"addr\" to the SNAT IP addr, and \"from_endpoint\" to true\n * if the packet is sent from a local endpoint.\n *\n * Callers should treat contents of \"from_endpoint\" and \"addr\" as undetermined,\n * if function returns false.\n */"
    },
    {
      "start_line": 1114,
      "end_line": 1117,
      "text": "/* Basic minimum is to only NAT when there is a potential of\n\t * overlapping tuples, e.g. applications in hostns reusing\n\t * source IPs we SNAT in NodePort and BPF-masq.\n\t */"
    },
    {
      "start_line": 1124,
      "end_line": 1127,
      "text": "/* NATIVE_DEV_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into\n     * preprocessor, as the former is known only during load time (templating).\n     * This checks whether bpf_host is running on the direct routing device.\n     */"
    },
    {
      "start_line": 1139,
      "end_line": 1139,
      "text": "/* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */"
    },
    {
      "start_line": 1144,
      "end_line": 1150,
      "text": "/* Check if this packet belongs to reply traffic coming from a\n\t * local endpoint.\n\t *\n\t * If local_ep is NULL, it means there's no endpoint running on the\n\t * node which matches the packet source IP, which means we can\n\t * skip the CT lookup since this cannot be reply traffic.\n\t */"
    },
    {
      "start_line": 1162,
      "end_line": 1162,
      "text": "/* SNAT local pod to world packets */"
    },
    {
      "start_line": 1164,
      "end_line": 1167,
      "text": "/* Do not MASQ when this function is executed from bpf_overlay\n\t * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will\n\t * be SNAT'd to cilium_host IP addr.\n\t */"
    },
    {
      "start_line": 1171,
      "end_line": 1176,
      "text": "/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.\n *\n * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as\n * the destination may be in the SNAT exclusion CIDR but regardless of that we\n * always want to SNAT a packet if it's matched by an egress NAT policy.\n */"
    },
    {
      "start_line": 1178,
      "end_line": 1181,
      "text": "/* If the packet is destined to an entity inside the cluster, either EP\n\t * or node, skip SNAT since only traffic leaving the cluster is supposed\n\t * to be masqueraded with an egress IP.\n\t */"
    },
    {
      "start_line": 1186,
      "end_line": 1188,
      "text": "/* If the packet is a reply it means that outside has initiated the\n\t * connection, so no need to SNAT the reply.\n\t */"
    },
    {
      "start_line": 1205,
      "end_line": 1210,
      "text": "/* Do not MASQ if a dst IP belongs to a pods CIDR\n\t * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).\n\t * The check is performed before we determine that a packet is\n\t * sent from a local pod, as this check is cheaper than\n\t * the map lookup done in the latter check.\n\t */"
    },
    {
      "start_line": 1216,
      "end_line": 1216,
      "text": "/* if this is a localhost endpoint, no SNAT is needed */"
    },
    {
      "start_line": 1222,
      "end_line": 1224,
      "text": "/* Do not SNAT if dst belongs to any ip-masq-agent\n\t\t * subnet.\n\t\t */"
    },
    {
      "start_line": 1233,
      "end_line": 1241,
      "text": "/* In the tunnel mode, a packet from a local ep\n\t\t * to a remote node is not encap'd, and is sent\n\t\t * via a native dev. Therefore, such packet has\n\t\t * to be MASQ'd. Otherwise, it might be dropped\n\t\t * either by underlying network (e.g. AWS drops\n\t\t * packets by default from unknown subnets) or\n\t\t * by the remote node if its native dev's\n\t\t * rp_filter=1.\n\t\t */"
    },
    {
      "start_line": 1246,
      "end_line": 1249,
      "text": "/* If the packet is a reply it means that outside has\n\t\t * initiated the connection, so no need to SNAT the\n\t\t * reply.\n\t\t */"
    },
    {
      "start_line": 1256,
      "end_line": 1256,
      "text": "/*ENABLE_MASQUERADE */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " IP_MASQ_AGENT_IPV4"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __be32 *addr",
    " bool * from_endpoint __maybe_unused"
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
    "static __always_inline bool snat_v4_needed (struct  __ctx_buff *ctx, __be32 *addr, bool * from_endpoint __maybe_unused)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    struct endpoint_info * local_ep __maybe_unused;\n",
    "    struct remote_endpoint_info * remote_ep __maybe_unused;\n",
    "    struct egress_gw_policy_entry * egress_gw_policy __maybe_unused;\n",
    "    bool is_reply = false;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return false;\n",
    "\n",
    "#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)\n",
    "    if (ip4->saddr == IPV4_GATEWAY) {\n",
    "        *addr = IPV4_GATEWAY;\n",
    "        return true;\n",
    "    }\n",
    "\n",
    "#else\n",
    "    if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX && ip4->saddr == IPV4_DIRECT_ROUTING) {\n",
    "        *addr = IPV4_DIRECT_ROUTING;\n",
    "        return true;\n",
    "    }\n",
    "\n",
    "# ifdef ENABLE_MASQUERADE\n",
    "    if (ip4->saddr == IPV4_MASQUERADE) {\n",
    "        *addr = IPV4_MASQUERADE;\n",
    "        return true;\n",
    "    }\n",
    "\n",
    "# endif\n",
    "\n",
    "#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */\n",
    "    local_ep = __lookup_ip4_endpoint (ip4 -> saddr);\n",
    "    remote_ep = lookup_ip4_remote_endpoint (ip4 -> daddr);\n",
    "    if (local_ep) {\n",
    "        struct ipv4_ct_tuple tuple = {\n",
    "            .nexthdr = ip4->protocol,\n",
    "            .daddr = ip4->daddr,\n",
    "            .saddr = ip4->saddr}\n",
    "        ;\n",
    "        ct_is_reply4 (get_ct_map4 (&tuple), ctx, ETH_HLEN + ipv4_hdrlen (ip4), &tuple, &is_reply);\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_MASQUERADE /* SNAT local pod to world packets */\n",
    "\n",
    "# ifdef IS_BPF_OVERLAY\n",
    "    return false;\n",
    "\n",
    "# endif\n",
    "\n",
    "#if defined(ENABLE_EGRESS_GATEWAY)\n",
    "    if (remote_ep && identity_is_cluster (remote_ep->sec_label))\n",
    "        goto skip_egress_gateway;\n",
    "    if (is_reply)\n",
    "        goto skip_egress_gateway;\n",
    "    egress_gw_policy = lookup_ip4_egress_gw_policy (ip4 -> saddr, ip4 -> daddr);\n",
    "    if (!egress_gw_policy)\n",
    "        goto skip_egress_gateway;\n",
    "    *addr = egress_gw_policy->egress_ip;\n",
    "    *from_endpoint = true;\n",
    "    return true;\n",
    "skip_egress_gateway :\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR\n",
    "    if (ipv4_is_in_subnet (ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR, IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))\n",
    "        return false;\n",
    "\n",
    "#endif\n",
    "    if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))\n",
    "        return false;\n",
    "    if (remote_ep) {\n",
    "\n",
    "#ifdef ENABLE_IP_MASQ_AGENT\n",
    "        struct lpm_v4_key pfx;\n",
    "        pfx.lpm.prefixlen = 32;\n",
    "        memcpy (pfx.lpm.data, &ip4->daddr, sizeof (pfx.addr));\n",
    "        if (map_lookup_elem (&IP_MASQ_AGENT_IPV4, &pfx))\n",
    "            return false;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifndef TUNNEL_MODE\n",
    "        if (identity_is_remote_node (remote_ep->sec_label))\n",
    "            return false;\n",
    "\n",
    "#endif\n",
    "        if (!is_reply && local_ep) {\n",
    "            *from_endpoint = true;\n",
    "            *addr = IPV4_MASQUERADE;\n",
    "            return true;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /*ENABLE_MASQUERADE */\n",
    "    return false;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "memcpy",
    "ipv4_hdrlen",
    "lookup_ip4_egress_gw_policy",
    "__lookup_ip4_endpoint",
    "defined",
    "ct_is_reply4",
    "ipv4_is_in_subnet",
    "get_ct_map4",
    "identity_is_cluster",
    "identity_is_remote_node",
    "lookup_ip4_remote_endpoint"
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
static __always_inline bool snat_v4_needed(struct __ctx_buff *ctx, __be32 *addr,
					   bool *from_endpoint __maybe_unused)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct egress_gw_policy_entry *egress_gw_policy __maybe_unused;
	bool is_reply = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in NodePort and BPF-masq.
	 */
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		*addr = IPV4_GATEWAY;
		return true;
	}
#else
    /* NATIVE_DEV_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into
     * preprocessor, as the former is known only during load time (templating).
     * This checks whether bpf_host is running on the direct routing device.
     */
	if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX &&
	    ip4->saddr == IPV4_DIRECT_ROUTING) {
		*addr = IPV4_DIRECT_ROUTING;
		return true;
	}
# ifdef ENABLE_MASQUERADE
	if (ip4->saddr == IPV4_MASQUERADE) {
		*addr = IPV4_MASQUERADE;
		return true;
	}
# endif
#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */

	local_ep = __lookup_ip4_endpoint(ip4->saddr);
	remote_ep = lookup_ip4_remote_endpoint(ip4->daddr);

	/* Check if this packet belongs to reply traffic coming from a
	 * local endpoint.
	 *
	 * If local_ep is NULL, it means there's no endpoint running on the
	 * node which matches the packet source IP, which means we can
	 * skip the CT lookup since this cannot be reply traffic.
	 */
	if (local_ep) {
		struct ipv4_ct_tuple tuple = {
			.nexthdr = ip4->protocol,
			.daddr = ip4->daddr,
			.saddr = ip4->saddr
		};

		ct_is_reply4(get_ct_map4(&tuple), ctx, ETH_HLEN +
			     ipv4_hdrlen(ip4), &tuple, &is_reply);
	}

#ifdef ENABLE_MASQUERADE /* SNAT local pod to world packets */
# ifdef IS_BPF_OVERLAY
	/* Do not MASQ when this function is executed from bpf_overlay
	 * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will
	 * be SNAT'd to cilium_host IP addr.
	 */
	return false;
# endif

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
 *
 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
 * the destination may be in the SNAT exclusion CIDR but regardless of that we
 * always want to SNAT a packet if it's matched by an egress NAT policy.
 */
#if defined(ENABLE_EGRESS_GATEWAY)
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_label))
		goto skip_egress_gateway;

	/* If the packet is a reply it means that outside has initiated the
	 * connection, so no need to SNAT the reply.
	 */
	if (is_reply)
		goto skip_egress_gateway;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
	if (!egress_gw_policy)
		goto skip_egress_gateway;

	*addr = egress_gw_policy->egress_ip;
	*from_endpoint = true;

	return true;

skip_egress_gateway:
#endif

#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 * The check is performed before we determine that a packet is
	 * sent from a local pod, as this check is cheaper than
	 * the map lookup done in the latter check.
	 */
	if (ipv4_is_in_subnet(ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return false;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return false;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT
		/* Do not SNAT if dst belongs to any ip-masq-agent
		 * subnet.
		 */
		struct lpm_v4_key pfx;

		pfx.lpm.prefixlen = 32;
		memcpy(pfx.lpm.data, &ip4->daddr, sizeof(pfx.addr));
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV4, &pfx))
			return false;
#endif
#ifndef TUNNEL_MODE
		/* In the tunnel mode, a packet from a local ep
		 * to a remote node is not encap'd, and is sent
		 * via a native dev. Therefore, such packet has
		 * to be MASQ'd. Otherwise, it might be dropped
		 * either by underlying network (e.g. AWS drops
		 * packets by default from unknown subnets) or
		 * by the remote node if its native dev's
		 * rp_filter=1.
		 */
		if (identity_is_remote_node(remote_ep->sec_label))
			return false;
#endif

		/* If the packet is a reply it means that outside has
		 * initiated the connection, so no need to SNAT the
		 * reply.
		 */
		if (!is_reply && local_ep) {
			*from_endpoint = true;
			*addr = IPV4_MASQUERADE;
			return true;
		}
	}
#endif /*ENABLE_MASQUERADE */

	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1261,
  "endLine": 1278,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_nat_ipv4_fwd",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int nodeport_nat_ipv4_fwd (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    bool from_endpoint = false;\n",
    "    struct ipv4_nat_target target = {\n",
    "        .min_port = NODEPORT_PORT_MIN_NAT,\n",
    "        .max_port = NODEPORT_PORT_MAX_NAT,\n",
    "        .addr = 0,}\n",
    "    ;\n",
    "    int ret = CTX_ACT_OK;\n",
    "    if (snat_v4_needed (ctx, &target.addr, &from_endpoint))\n",
    "        ret = snat_v4_process (ctx, NAT_DIR_EGRESS, &target, from_endpoint);\n",
    "    if (ret == NAT_PUNT_TO_STACK)\n",
    "        ret = CTX_ACT_OK;\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v4_process",
    "snat_v4_needed"
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
static __always_inline int nodeport_nat_ipv4_fwd(struct __ctx_buff *ctx)
{
	bool from_endpoint = false;
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.addr = 0,
	};
	int ret = CTX_ACT_OK;

	if (snat_v4_needed(ctx, &target.addr, &from_endpoint))
		ret = snat_v4_process(ctx, NAT_DIR_EGRESS, &target,
				      from_endpoint);
	if (ret == NAT_PUNT_TO_STACK)
		ret = CTX_ACT_OK;

	return ret;
}

#ifdef ENABLE_DSR
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1282,
  "endLine": 1290,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "rss_gen_src4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__be32 client",
    " __be32 l4_hint"
  ],
  "output": "static__always_inline__be32",
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
    "static __always_inline __be32 rss_gen_src4 (__be32 client, __be32 l4_hint)\n",
    "{\n",
    "    const __u32 bits = 32 - IPV4_RSS_PREFIX_BITS;\n",
    "    __be32 src = IPV4_RSS_PREFIX;\n",
    "    if (bits)\n",
    "        src |= bpf_htonl (hash_32 (client ^ l4_hint, bits));\n",
    "    return src;\n",
    "}\n"
  ],
  "called_function_list": [
    "hash_32",
    "bpf_htonl"
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
static __always_inline __be32 rss_gen_src4(__be32 client, __be32 l4_hint)
{
	const __u32 bits = 32 - IPV4_RSS_PREFIX_BITS;
	__be32 src = IPV4_RSS_PREFIX;

	if (bits)
		src |= bpf_htonl(hash_32(client ^ l4_hint, bits));
	return src;
}

/*
 * Original packet: [clientIP:clientPort -> serviceIP:servicePort] } IP/L4
 *
 * After DSR IPIP:  [rssSrcIP -> backendIP]                        } IP
 *                  [clientIP:clientPort -> serviceIP:servicePort] } IP/L4
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1298,
  "endLine": 1350,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_set_ipip4",
  "developer_inline_comments": [
    {
      "start_line": 1292,
      "end_line": 1297,
      "text": "/*\n * Original packet: [clientIP:clientPort -> serviceIP:servicePort] } IP/L4\n *\n * After DSR IPIP:  [rssSrcIP -> backendIP]                        } IP\n *                  [clientIP:clientPort -> serviceIP:servicePort] } IP/L4\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct iphdr *ip4",
    " __be32 backend_addr",
    " __be32 l4_hint",
    " __be16 *ohead"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_seg6local",
    "sched_act",
    "xdp",
    "lwt_xmit",
    "sched_cls",
    "lwt_in",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int dsr_set_ipip4 (struct  __ctx_buff *ctx, const struct iphdr *ip4, __be32 backend_addr, __be32 l4_hint, __be16 *ohead)\n",
    "{\n",
    "    __u16 tot_len = bpf_ntohs (ip4->tot_len) + sizeof (*ip4);\n",
    "    const int l3_off = ETH_HLEN;\n",
    "    __be32 sum;\n",
    "    struct {\n",
    "        __be16 tot_len;\n",
    "        __be16 id;\n",
    "        __be16 frag_off;\n",
    "        __u8 ttl;\n",
    "        __u8 protocol;\n",
    "        __be32 saddr;\n",
    "        __be32 daddr;\n",
    "    } tp_old = {\n",
    "        .tot_len = ip4->tot_len,\n",
    "        .ttl = ip4->ttl,\n",
    "        .protocol = ip4->protocol,\n",
    "        .saddr = ip4->saddr,\n",
    "        .daddr = ip4->daddr,}, tp_new = {\n",
    "        .tot_len = bpf_htons (tot_len),\n",
    "        .ttl = IPDEFTTL,\n",
    "        .protocol = IPPROTO_IPIP,\n",
    "        .saddr = rss_gen_src4 (ip4->saddr, l4_hint),\n",
    "        .daddr = backend_addr,};\n",
    "\n",
    "    if (dsr_is_too_big (ctx, tot_len)) {\n",
    "        *ohead = sizeof (*ip4);\n",
    "        return DROP_FRAG_NEEDED;\n",
    "    }\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (*ip4), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    sum = csum_diff (& tp_old, 16, & tp_new, 16, 0);\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, tot_len), &tp_new.tot_len, 2, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, ttl), &tp_new.ttl, 2, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, saddr), &tp_new.saddr, 8, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (l3_csum_replace (ctx, l3_off + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_adjust_hroom_dsr_flags",
    "dsr_is_too_big",
    "bpf_ntohs",
    "rss_gen_src4",
    "ctx_store_bytes",
    "ctx_adjust_hroom",
    "offsetof",
    "bpf_htons"
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
static __always_inline int dsr_set_ipip4(struct __ctx_buff *ctx,
					 const struct iphdr *ip4,
					 __be32 backend_addr,
					 __be32 l4_hint, __be16 *ohead)
{
	__u16 tot_len = bpf_ntohs(ip4->tot_len) + sizeof(*ip4);
	const int l3_off = ETH_HLEN;
	__be32 sum;
	struct {
		__be16 tot_len;
		__be16 id;
		__be16 frag_off;
		__u8   ttl;
		__u8   protocol;
		__be32 saddr;
		__be32 daddr;
	} tp_old = {
		.tot_len	= ip4->tot_len,
		.ttl		= ip4->ttl,
		.protocol	= ip4->protocol,
		.saddr		= ip4->saddr,
		.daddr		= ip4->daddr,
	}, tp_new = {
		.tot_len	= bpf_htons(tot_len),
		.ttl		= IPDEFTTL,
		.protocol	= IPPROTO_IPIP,
		.saddr		= rss_gen_src4(ip4->saddr, l4_hint),
		.daddr		= backend_addr,
	};

	if (dsr_is_too_big(ctx, tot_len)) {
		*ohead = sizeof(*ip4);
		return DROP_FRAG_NEEDED;
	}

	if (ctx_adjust_hroom(ctx, sizeof(*ip4), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
		return DROP_INVALID;
	sum = csum_diff(&tp_old, 16, &tp_new, 16, 0);
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, tot_len),
			    &tp_new.tot_len, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, ttl),
			    &tp_new.ttl, 2, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
			    &tp_new.saddr, 8, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	return 0;
}
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1352,
  "endLine": 1404,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_set_opt4",
  "developer_inline_comments": [
    {
      "start_line": 1367,
      "end_line": 1371,
      "text": "/* Setting the option is required only for the first packet\n\t\t * (SYN), in the case of TCP, as for further packets of the\n\t\t * same connection a remote node will use a NAT entry to\n\t\t * reverse xlate a reply.\n\t\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct iphdr *ip4",
    " __be32 svc_addr",
    " __be32 svc_port",
    " __be16 *ohead"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_seg6local",
    "sched_act",
    "xdp",
    "lwt_xmit",
    "sched_cls",
    "lwt_in",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int dsr_set_opt4 (struct  __ctx_buff *ctx, struct iphdr *ip4, __be32 svc_addr, __be32 svc_port, __be16 *ohead)\n",
    "{\n",
    "    __u32 iph_old, iph_new, opt [2];\n",
    "    __u16 tot_len = bpf_ntohs (ip4->tot_len) + sizeof (opt);\n",
    "    __be32 sum;\n",
    "    if (ip4->protocol == IPPROTO_TCP) {\n",
    "        union tcp_flags tcp_flags = {\n",
    "            .value = 0}\n",
    "        ;\n",
    "        if (ctx_load_bytes (ctx, ETH_HLEN + sizeof (*ip4) + 12, &tcp_flags, 2) < 0)\n",
    "            return DROP_CT_INVALID_HDR;\n",
    "        if (!(tcp_flags.value & (TCP_FLAG_SYN)))\n",
    "            return 0;\n",
    "    }\n",
    "    if (dsr_is_too_big (ctx, tot_len)) {\n",
    "        *ohead = sizeof (opt);\n",
    "        return DROP_FRAG_NEEDED;\n",
    "    }\n",
    "    iph_old = *(__u32*) ip4;\n",
    "    ip4->ihl += sizeof (opt) >> 2;\n",
    "    ip4->tot_len = bpf_htons (tot_len);\n",
    "    iph_new = *(__u32*) ip4;\n",
    "    opt[0] = bpf_htonl (DSR_IPV4_OPT_32 | svc_port);\n",
    "    opt[1] = bpf_htonl (svc_addr);\n",
    "    sum = csum_diff (& iph_old, 4, & iph_new, 4, 0);\n",
    "    sum = csum_diff (NULL, 0, & opt, sizeof (opt), sum);\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (opt), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + sizeof (*ip4), &opt, sizeof (opt), 0) < 0)\n",
    "        return DROP_INVALID;\n",
    "    if (l3_csum_replace (ctx, ETH_HLEN + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_adjust_hroom_dsr_flags",
    "dsr_is_too_big",
    "bpf_ntohs",
    "bpf_htonl",
    "ctx_store_bytes",
    "ctx_adjust_hroom",
    "ctx_load_bytes",
    "offsetof",
    "bpf_htons"
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
static __always_inline int dsr_set_opt4(struct __ctx_buff *ctx,
					struct iphdr *ip4, __be32 svc_addr,
					__be32 svc_port, __be16 *ohead)
{
	__u32 iph_old, iph_new, opt[2];
	__u16 tot_len = bpf_ntohs(ip4->tot_len) + sizeof(opt);
	__be32 sum;

	if (ip4->protocol == IPPROTO_TCP) {
		union tcp_flags tcp_flags = { .value = 0 };

		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(*ip4) + 12,
				   &tcp_flags, 2) < 0)
			return DROP_CT_INVALID_HDR;

		/* Setting the option is required only for the first packet
		 * (SYN), in the case of TCP, as for further packets of the
		 * same connection a remote node will use a NAT entry to
		 * reverse xlate a reply.
		 */
		if (!(tcp_flags.value & (TCP_FLAG_SYN)))
			return 0;
	}

	if (dsr_is_too_big(ctx, tot_len)) {
		*ohead = sizeof(opt);
		return DROP_FRAG_NEEDED;
	}

	iph_old = *(__u32 *)ip4;
	ip4->ihl += sizeof(opt) >> 2;
	ip4->tot_len = bpf_htons(tot_len);
	iph_new = *(__u32 *)ip4;

	opt[0] = bpf_htonl(DSR_IPV4_OPT_32 | svc_port);
	opt[1] = bpf_htonl(svc_addr);

	sum = csum_diff(&iph_old, 4, &iph_new, 4, 0);
	sum = csum_diff(NULL, 0, &opt, sizeof(opt), sum);

	if (ctx_adjust_hroom(ctx, sizeof(opt), BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()))
		return DROP_INVALID;

	if (ctx_store_bytes(ctx, ETH_HLEN + sizeof(*ip4),
			    &opt, sizeof(opt), 0) < 0)
		return DROP_INVALID;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;

	return 0;
}
#endif /* DSR_ENCAP_MODE */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1407,
  "endLine": 1446,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "handle_dsr_v4",
  "developer_inline_comments": [
    {
      "start_line": 1415,
      "end_line": 1417,
      "text": "/* Check whether IPv4 header contains a 64-bit option (IPv4 header\n\t * w/o option (5 x 32-bit words) + the DSR option (2 x 32-bit words)).\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " bool *dsr"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int handle_dsr_v4 (struct  __ctx_buff *ctx, bool *dsr)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    if (ip4->ihl == 0x7) {\n",
    "        __u32 opt1 = 0, opt2 = 0;\n",
    "        __be32 address;\n",
    "        __be16 dport;\n",
    "        if (ctx_load_bytes (ctx, ETH_HLEN + sizeof (struct iphdr), &opt1, sizeof (opt1)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        opt1 = bpf_ntohl (opt1);\n",
    "        if ((opt1 & DSR_IPV4_OPT_MASK) == DSR_IPV4_OPT_32) {\n",
    "            if (ctx_load_bytes (ctx, ETH_HLEN + sizeof (struct iphdr) + sizeof (opt1), &opt2, sizeof (opt2)) < 0)\n",
    "                return DROP_INVALID;\n",
    "            opt2 = bpf_ntohl (opt2);\n",
    "            dport = opt1 & DSR_IPV4_DPORT_MASK;\n",
    "            address = opt2;\n",
    "            *dsr = true;\n",
    "            if (snat_v4_create_dsr (ctx, address, dport) < 0)\n",
    "                return DROP_INVALID;\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohl",
    "ctx_load_bytes",
    "revalidate_data",
    "snat_v4_create_dsr"
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
static __always_inline int handle_dsr_v4(struct __ctx_buff *ctx, bool *dsr)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Check whether IPv4 header contains a 64-bit option (IPv4 header
	 * w/o option (5 x 32-bit words) + the DSR option (2 x 32-bit words)).
	 */
	if (ip4->ihl == 0x7) {
		__u32 opt1 = 0, opt2 = 0;
		__be32 address;
		__be16 dport;

		if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(struct iphdr),
				   &opt1, sizeof(opt1)) < 0)
			return DROP_INVALID;

		opt1 = bpf_ntohl(opt1);
		if ((opt1 & DSR_IPV4_OPT_MASK) == DSR_IPV4_OPT_32) {
			if (ctx_load_bytes(ctx, ETH_HLEN +
					   sizeof(struct iphdr) +
					   sizeof(opt1),
					   &opt2, sizeof(opt2)) < 0)
				return DROP_INVALID;

			opt2 = bpf_ntohl(opt2);
			dport = opt1 & DSR_IPV4_DPORT_MASK;
			address = opt2;
			*dsr = true;

			if (snat_v4_create_dsr(ctx, address, dport) < 0)
				return DROP_INVALID;
		}
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1448,
  "endLine": 1464,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "xlate_dsr_v4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ipv4_ct_tuple *tuple",
    " int l4_off",
    " bool has_l4_header"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int xlate_dsr_v4 (struct  __ctx_buff *ctx, const struct ipv4_ct_tuple *tuple, int l4_off, bool has_l4_header)\n",
    "{\n",
    "    struct ipv4_ct_tuple nat_tup = *tuple;\n",
    "    struct ipv4_nat_entry *entry;\n",
    "    int ret = 0;\n",
    "    nat_tup.flags = NAT_DIR_EGRESS;\n",
    "    nat_tup.sport = tuple->dport;\n",
    "    nat_tup.dport = tuple->sport;\n",
    "    entry = snat_v4_lookup (& nat_tup);\n",
    "    if (entry)\n",
    "        ret = snat_v4_rewrite_egress (ctx, &nat_tup, entry, l4_off, has_l4_header);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v4_rewrite_egress",
    "snat_v4_lookup"
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
static __always_inline int xlate_dsr_v4(struct __ctx_buff *ctx,
					const struct ipv4_ct_tuple *tuple,
					int l4_off, bool has_l4_header)
{
	struct ipv4_ct_tuple nat_tup = *tuple;
	struct ipv4_nat_entry *entry;
	int ret = 0;

	nat_tup.flags = NAT_DIR_EGRESS;
	nat_tup.sport = tuple->dport;
	nat_tup.dport = tuple->sport;

	entry = snat_v4_lookup(&nat_tup);
	if (entry)
		ret = snat_v4_rewrite_egress(ctx, &nat_tup, entry, l4_off, has_l4_header);
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1466,
  "endLine": 1549,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "dsr_reply_icmp4",
  "developer_inline_comments": [
    {
      "start_line": 1511,
      "end_line": 1514,
      "text": "/* We use a workaround here in that we push zero-bytes into the\n\t * payload in order to support dynamic IPv4 header size. This\n\t * works given one's complement sum does not change.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct iphdr * ip4 __maybe_unused",
    " int code",
    " __be16 ohead __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_seg6local",
    "sched_act",
    "xdp",
    "lwt_xmit",
    "sched_cls",
    "lwt_in",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int dsr_reply_icmp4 (struct  __ctx_buff *ctx, struct iphdr * ip4 __maybe_unused, int code, __be16 ohead __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_DSR_ICMP_ERRORS\n",
    "    const __s32 orig_dgram = 8, off = ETH_HLEN;\n",
    "    const __u32 l3_max = MAX_IPOPTLEN + sizeof (*ip4) + orig_dgram;\n",
    "    __be16 type = bpf_htons (ETH_P_IP);\n",
    "    __s32 len_new = off + ipv4_hdrlen (ip4) + orig_dgram;\n",
    "    __s32 len_old = ctx_full_len (ctx);\n",
    "    __u8 reason = (__u8) -code;\n",
    "    __u8 tmp [l3_max];\n",
    "    union macaddr smac, dmac;\n",
    "    struct icmphdr icmp __align_stack_8 = {\n",
    "        .type = ICMP_DEST_UNREACH,\n",
    "        .code = ICMP_FRAG_NEEDED,\n",
    "        .un = {\n",
    "            .frag = {\n",
    "                .mtu = bpf_htons (THIS_MTU - ohead),},},}\n",
    "    ;\n",
    "    __u64 tot_len = sizeof (struct iphdr) + ipv4_hdrlen (ip4) + sizeof (icmp) + orig_dgram;\n",
    "    struct iphdr ip __align_stack_8 = {\n",
    "        .ihl = sizeof (ip) >> 2,\n",
    "        .version = IPVERSION,\n",
    "        .ttl = IPDEFTTL,\n",
    "        .tos = ip4->tos,\n",
    "        .id = ip4->id,\n",
    "        .protocol = IPPROTO_ICMP,\n",
    "        .saddr = ip4->daddr,\n",
    "        .daddr = ip4->saddr,\n",
    "        .frag_off = bpf_htons (IP_DF),\n",
    "        .tot_len = bpf_htons ((__u16) tot_len),}\n",
    "    ;\n",
    "    update_metrics (ctx_full_len (ctx), METRIC_EGRESS, reason);\n",
    "    if (eth_load_saddr (ctx, smac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_load_daddr (ctx, dmac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    ip.check = csum_fold (csum_diff (NULL, 0, &ip, sizeof (ip), 0));\n",
    "    memset (tmp, 0, MAX_IPOPTLEN);\n",
    "    if (ctx_store_bytes (ctx, len_new, tmp, MAX_IPOPTLEN, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_load_bytes (ctx, off, tmp, sizeof (tmp)) < 0)\n",
    "        goto drop_err;\n",
    "    icmp.checksum = csum_fold (csum_diff (NULL, 0, tmp, sizeof (tmp), csum_diff (NULL, 0, &icmp, sizeof (icmp), 0)));\n",
    "    if (ctx_adjust_troom (ctx, -(len_old - len_new)) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_adjust_hroom (ctx, sizeof (ip) + sizeof (icmp), BPF_ADJ_ROOM_NET, ctx_adjust_hroom_dsr_flags ()) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_store_daddr (ctx, smac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (eth_store_saddr (ctx, dmac.addr, 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, ETH_ALEN * 2, &type, sizeof (type), 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, off, &ip, sizeof (ip), 0) < 0)\n",
    "        goto drop_err;\n",
    "    if (ctx_store_bytes (ctx, off + sizeof (ip), &icmp, sizeof (icmp), 0) < 0)\n",
    "        goto drop_err;\n",
    "    return ctx_redirect (ctx, ctx_get_ifindex (ctx), 0);\n",
    "drop_err :\n",
    "\n",
    "#endif\n",
    "    return send_drop_notify_error (ctx, 0, code, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "eth_load_saddr",
    "csum_fold",
    "memset",
    "eth_store_saddr",
    "ipv4_hdrlen",
    "ctx_adjust_hroom_dsr_flags",
    "ctx_adjust_troom",
    "ctx_store_bytes",
    "eth_store_daddr",
    "ctx_get_ifindex",
    "send_drop_notify_error",
    "ctx_adjust_hroom",
    "ctx_load_bytes",
    "ctx_redirect",
    "ctx_full_len",
    "eth_load_daddr",
    "update_metrics",
    "bpf_htons"
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
static __always_inline int dsr_reply_icmp4(struct __ctx_buff *ctx,
					   struct iphdr *ip4 __maybe_unused,
					   int code, __be16 ohead __maybe_unused)
{
#ifdef ENABLE_DSR_ICMP_ERRORS
	const __s32 orig_dgram = 8, off = ETH_HLEN;
	const __u32 l3_max = MAX_IPOPTLEN + sizeof(*ip4) + orig_dgram;
	__be16 type = bpf_htons(ETH_P_IP);
	__s32 len_new = off + ipv4_hdrlen(ip4) + orig_dgram;
	__s32 len_old = ctx_full_len(ctx);
	__u8 reason = (__u8)-code;
	__u8 tmp[l3_max];
	union macaddr smac, dmac;
	struct icmphdr icmp __align_stack_8 = {
		.type		= ICMP_DEST_UNREACH,
		.code		= ICMP_FRAG_NEEDED,
		.un = {
			.frag = {
				.mtu = bpf_htons(THIS_MTU - ohead),
			},
		},
	};
	__u64 tot_len = sizeof(struct iphdr) + ipv4_hdrlen(ip4) + sizeof(icmp) + orig_dgram;
	struct iphdr ip __align_stack_8 = {
		.ihl		= sizeof(ip) >> 2,
		.version	= IPVERSION,
		.ttl		= IPDEFTTL,
		.tos		= ip4->tos,
		.id		= ip4->id,
		.protocol	= IPPROTO_ICMP,
		.saddr		= ip4->daddr,
		.daddr		= ip4->saddr,
		.frag_off	= bpf_htons(IP_DF),
		.tot_len	= bpf_htons((__u16)tot_len),
	};

	update_metrics(ctx_full_len(ctx), METRIC_EGRESS, reason);

	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_load_daddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;

	ip.check = csum_fold(csum_diff(NULL, 0, &ip, sizeof(ip), 0));

	/* We use a workaround here in that we push zero-bytes into the
	 * payload in order to support dynamic IPv4 header size. This
	 * works given one's complement sum does not change.
	 */
	memset(tmp, 0, MAX_IPOPTLEN);
	if (ctx_store_bytes(ctx, len_new, tmp, MAX_IPOPTLEN, 0) < 0)
		goto drop_err;
	if (ctx_load_bytes(ctx, off, tmp, sizeof(tmp)) < 0)
		goto drop_err;

	icmp.checksum = csum_fold(csum_diff(NULL, 0, tmp, sizeof(tmp),
					    csum_diff(NULL, 0, &icmp,
						      sizeof(icmp), 0)));

	if (ctx_adjust_troom(ctx, -(len_old - len_new)) < 0)
		goto drop_err;
	if (ctx_adjust_hroom(ctx, sizeof(ip) + sizeof(icmp),
			     BPF_ADJ_ROOM_NET,
			     ctx_adjust_hroom_dsr_flags()) < 0)
		goto drop_err;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0)
		goto drop_err;
	if (eth_store_saddr(ctx, dmac.addr, 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, ETH_ALEN * 2, &type, sizeof(type), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off, &ip, sizeof(ip), 0) < 0)
		goto drop_err;
	if (ctx_store_bytes(ctx, off + sizeof(ip), &icmp,
			    sizeof(icmp), 0) < 0)
		goto drop_err;

	return ctx_redirect(ctx, ctx_get_ifindex(ctx), 0);
drop_err:
#endif
	return send_drop_notify_error(ctx, 0, code, CTX_ACT_DROP,
				      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_DSR)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1552,
  "endLine": 1621,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_nodeport_ipv4_dsr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "fib_lookup",
    "bpf_fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_nodeport_ipv4_dsr (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct bpf_fib_lookup_padded fib_params = {\n",
    "        .l = {\n",
    "            .family = AF_INET,\n",
    "            .ifindex = ctx_get_ifindex (ctx),},}\n",
    "    ;\n",
    "    bool l2_hdr_required = true;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    __be16 ohead = 0;\n",
    "    int ret, ext_err = 0;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "\n",
    "#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "    ret = dsr_set_ipip4 (ctx, ip4, ctx_load_meta (ctx, CB_ADDR_V4), ctx_load_meta (ctx, CB_HINT), & ohead);\n",
    "\n",
    "#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE\n",
    "    ret = dsr_set_opt4 (ctx, ip4, ctx_load_meta (ctx, CB_ADDR_V4), ctx_load_meta (ctx, CB_PORT), & ohead);\n",
    "\n",
    "#else\n",
    "\n",
    "# error \"Invalid load balancer DSR encapsulation mode!\"\n",
    "\n",
    "#endif\n",
    "    if (unlikely (ret)) {\n",
    "        if (dsr_fail_needs_reply (ret))\n",
    "            return dsr_reply_icmp4 (ctx, ip4, ret, ohead);\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    fib_params.l.ipv4_src = ip4->saddr;\n",
    "    fib_params.l.ipv4_dst = ip4->daddr;\n",
    "    ret = fib_lookup (ctx, & fib_params.l, sizeof (fib_params), 0);\n",
    "    if (ret != 0) {\n",
    "        ext_err = ret;\n",
    "        ret = DROP_NO_FIB;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    ret = maybe_add_l2_hdr (ctx, fib_params.l.ifindex, & l2_hdr_required);\n",
    "    if (ret != 0)\n",
    "        goto drop_err;\n",
    "    if (!l2_hdr_required)\n",
    "        goto out_send;\n",
    "    if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "out_send :\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, fib_params.l.ifindex, 0);\n",
    "drop_err :\n",
    "    return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "dsr_set_opt4",
    "dsr_set_ipip4",
    "maybe_add_l2_hdr",
    "cilium_capture_out",
    "dsr_reply_icmp4",
    "eth_store_daddr",
    "ctx_get_ifindex",
    "unlikely",
    "ctx_redirect",
    "dsr_fail_needs_reply",
    "ctx_load_meta",
    "eth_store_saddr",
    "send_drop_notify_error_ext"
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
int tail_nodeport_ipv4_dsr(struct __ctx_buff *ctx)
{
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	bool l2_hdr_required = true;
	void *data, *data_end;
	struct iphdr *ip4;
	__be16 ohead = 0;
	int ret, ext_err = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	ret = dsr_set_ipip4(ctx, ip4,
			    ctx_load_meta(ctx, CB_ADDR_V4),
			    ctx_load_meta(ctx, CB_HINT), &ohead);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
	ret = dsr_set_opt4(ctx, ip4,
			   ctx_load_meta(ctx, CB_ADDR_V4),
			   ctx_load_meta(ctx, CB_PORT), &ohead);
#else
# error "Invalid load balancer DSR encapsulation mode!"
#endif
	if (unlikely(ret)) {
		if (dsr_fail_needs_reply(ret))
			return dsr_reply_icmp4(ctx, ip4, ret, ohead);
		goto drop_err;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.l.ipv4_src = ip4->saddr;
	fib_params.l.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ext_err = ret;
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);
}
#endif /* ENABLE_DSR */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_NAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1625,
  "endLine": 1767,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_nodeport_nat_ipv4",
  "developer_inline_comments": [
    {
      "start_line": 1644,
      "end_line": 1648,
      "text": "/* Unfortunately, the bpf_fib_lookup() is not able to set src IP addr.\n\t * So we need to assume that the direct routing device is going to be\n\t * used to fwd the NodePort request, thus SNAT-ing to its IP addr.\n\t * This will change once we have resolved GH#17158.\n\t */"
    },
    {
      "start_line": 1661,
      "end_line": 1669,
      "text": "/* The dir == NAT_DIR_EGRESS branch is executed for\n\t\t\t * N/S LB requests which needs to be fwd-ed to a remote\n\t\t\t * node. As the request came from outside, we need to\n\t\t\t * set the security id in the tunnel header to WORLD_ID.\n\t\t\t * Otherwise, the remote node will assume, that the\n\t\t\t * request originated from a cluster node which will\n\t\t\t * bypass any netpol which disallows LB requests from\n\t\t\t * outside.\n\t\t\t */"
    },
    {
      "start_line": 1681,
      "end_line": 1681,
      "text": "/* fib lookup not necessary when going over tunnel. */"
    },
    {
      "start_line": 1693,
      "end_line": 1695,
      "text": "/* Handles SNAT on NAT_DIR_EGRESS and reverse SNAT for reply packets\n\t * from remote backends on NAT_DIR_INGRESS.\n\t */"
    },
    {
      "start_line": 1698,
      "end_line": 1702,
      "text": "/* In case of no mapping, recircle back to main path. SNAT is very\n\t\t * expensive in terms of instructions (since we don't have BPF to\n\t\t * BPF calls as we use tail calls) and complexity, hence this is\n\t\t * done inside a tail call here.\n\t\t */"
    },
    {
      "start_line": 1716,
      "end_line": 1722,
      "text": "/* At this point we know that a reverse SNAT mapping exists.\n\t\t * Otherwise, we would have tail-called back to\n\t\t * CALL_IPV4_FROM_NETDEV in the code above. The existence of the\n\t\t * mapping is an indicator that the packet might be a reply from\n\t\t * a remote backend. So handle the service reverse DNAT (if\n\t\t * needed)\n\t\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "fib_lookup",
    "bpf_fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_nodeport_nat_ipv4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    enum nat_dir dir = (enum nat_dir) ctx_load_meta (ctx, CB_NAT);\n",
    "    struct bpf_fib_lookup_padded fib_params = {\n",
    "        .l = {\n",
    "            .family = AF_INET,\n",
    "            .ifindex = ctx_get_ifindex (ctx),},}\n",
    "    ;\n",
    "    struct ipv4_nat_target target = {\n",
    "        .min_port = NODEPORT_PORT_MIN_NAT,\n",
    "        .max_port = NODEPORT_PORT_MAX_NAT,\n",
    "        .src_from_world = true,}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    bool l2_hdr_required = true;\n",
    "    int ret, ext_err = 0;\n",
    "    target.addr = IPV4_DIRECT_ROUTING;\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    if (dir == NAT_DIR_EGRESS) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "            ret = DROP_INVALID;\n",
    "            goto drop_err;\n",
    "        }\n",
    "        info = ipcache_lookup4 (& IPCACHE_MAP, ip4 -> daddr, V4_CACHE_KEY_LEN);\n",
    "        if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "            ret = __encap_with_nodeid (ctx, info -> tunnel_endpoint, WORLD_ID, NOT_VTEP_DST, (enum trace_reason) CT_NEW, TRACE_PAYLOAD_LEN);\n",
    "            if (ret)\n",
    "                goto drop_err;\n",
    "            target.addr = IPV4_GATEWAY;\n",
    "            fib_params.l.ifindex = ENCAP_IFINDEX;\n",
    "            if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "                ret = DROP_WRITE_ERROR;\n",
    "                goto drop_err;\n",
    "            }\n",
    "            if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "                ret = DROP_WRITE_ERROR;\n",
    "                goto drop_err;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    ret = snat_v4_process (ctx, dir, & target, false);\n",
    "    if (IS_ERR (ret)) {\n",
    "        if (dir == NAT_DIR_INGRESS) {\n",
    "            bpf_skip_nodeport_set (ctx);\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_NETDEV);\n",
    "            ret = DROP_MISSED_TAIL_CALL;\n",
    "            goto drop_err;\n",
    "        }\n",
    "        if (ret != NAT_PUNT_TO_STACK)\n",
    "            goto drop_err;\n",
    "    }\n",
    "    bpf_mark_snat_done (ctx);\n",
    "    if (dir == NAT_DIR_INGRESS) {\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        goto drop_err;\n",
    "    }\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    if (fib_params.l.ifindex == ENCAP_IFINDEX)\n",
    "        goto out_send;\n",
    "\n",
    "#endif\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    fib_params.l.ipv4_src = ip4->saddr;\n",
    "    fib_params.l.ipv4_dst = ip4->daddr;\n",
    "    ret = fib_lookup (ctx, & fib_params.l, sizeof (fib_params), 0);\n",
    "    if (ret != 0) {\n",
    "        ext_err = ret;\n",
    "        ret = DROP_NO_FIB;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    ret = maybe_add_l2_hdr (ctx, fib_params.l.ifindex, & l2_hdr_required);\n",
    "    if (ret != 0)\n",
    "        goto drop_err;\n",
    "    if (!l2_hdr_required)\n",
    "        goto out_send;\n",
    "    if (eth_store_daddr (ctx, fib_params.l.dmac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (eth_store_saddr (ctx, fib_params.l.smac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "out_send :\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, fib_params.l.ifindex, 0);\n",
    "drop_err :\n",
    "    return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, dir == NAT_DIR_INGRESS ? METRIC_INGRESS : METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_skip_nodeport_set",
    "revalidate_data",
    "snat_v4_process",
    "maybe_add_l2_hdr",
    "cilium_capture_out",
    "bpf_mark_snat_done",
    "__encap_with_nodeid",
    "ipcache_lookup4",
    "eth_store_daddr",
    "ep_tail_call",
    "ctx_get_ifindex",
    "IS_ERR",
    "ctx_redirect",
    "ctx_load_meta",
    "eth_store_saddr",
    "send_drop_notify_error_ext"
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
int tail_nodeport_nat_ipv4(struct __ctx_buff *ctx)
{
	enum nat_dir dir = (enum nat_dir)ctx_load_meta(ctx, CB_NAT);
	struct bpf_fib_lookup_padded fib_params = {
		.l = {
			.family		= AF_INET,
			.ifindex	= ctx_get_ifindex(ctx),
		},
	};
	struct ipv4_nat_target target = {
		.min_port = NODEPORT_PORT_MIN_NAT,
		.max_port = NODEPORT_PORT_MAX_NAT,
		.src_from_world = true,
	};
	void *data, *data_end;
	struct iphdr *ip4;
	bool l2_hdr_required = true;
	int ret, ext_err = 0;

	/* Unfortunately, the bpf_fib_lookup() is not able to set src IP addr.
	 * So we need to assume that the direct routing device is going to be
	 * used to fwd the NodePort request, thus SNAT-ing to its IP addr.
	 * This will change once we have resolved GH#17158.
	 */
	target.addr = IPV4_DIRECT_ROUTING;
#ifdef TUNNEL_MODE
	if (dir == NAT_DIR_EGRESS) {
		struct remote_endpoint_info *info;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err;
		}

		info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
		if (info != NULL && info->tunnel_endpoint != 0) {
			/* The dir == NAT_DIR_EGRESS branch is executed for
			 * N/S LB requests which needs to be fwd-ed to a remote
			 * node. As the request came from outside, we need to
			 * set the security id in the tunnel header to WORLD_ID.
			 * Otherwise, the remote node will assume, that the
			 * request originated from a cluster node which will
			 * bypass any netpol which disallows LB requests from
			 * outside.
			 */
			ret = __encap_with_nodeid(ctx, info->tunnel_endpoint,
						  WORLD_ID,
						  NOT_VTEP_DST,
						  (enum trace_reason)CT_NEW,
						  TRACE_PAYLOAD_LEN);
			if (ret)
				goto drop_err;

			target.addr = IPV4_GATEWAY;
			fib_params.l.ifindex = ENCAP_IFINDEX;

			/* fib lookup not necessary when going over tunnel. */
			if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
			if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
				ret = DROP_WRITE_ERROR;
				goto drop_err;
			}
		}
	}
#endif
	/* Handles SNAT on NAT_DIR_EGRESS and reverse SNAT for reply packets
	 * from remote backends on NAT_DIR_INGRESS.
	 */
	ret = snat_v4_process(ctx, dir, &target, false);
	if (IS_ERR(ret)) {
		/* In case of no mapping, recircle back to main path. SNAT is very
		 * expensive in terms of instructions (since we don't have BPF to
		 * BPF calls as we use tail calls) and complexity, hence this is
		 * done inside a tail call here.
		 */
		if (dir == NAT_DIR_INGRESS) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
			ret = DROP_MISSED_TAIL_CALL;
			goto drop_err;
		}
		if (ret != NAT_PUNT_TO_STACK)
			goto drop_err;
	}

	bpf_mark_snat_done(ctx);

	if (dir == NAT_DIR_INGRESS) {
		/* At this point we know that a reverse SNAT mapping exists.
		 * Otherwise, we would have tail-called back to
		 * CALL_IPV4_FROM_NETDEV in the code above. The existence of the
		 * mapping is an indicator that the packet might be a reply from
		 * a remote backend. So handle the service reverse DNAT (if
		 * needed)
		 */
		ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
		ret = DROP_MISSED_TAIL_CALL;
		goto drop_err;
	}
#ifdef TUNNEL_MODE
	if (fib_params.l.ifindex == ENCAP_IFINDEX)
		goto out_send;
#endif
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	fib_params.l.ipv4_src = ip4->saddr;
	fib_params.l.ipv4_dst = ip4->daddr;

	ret = fib_lookup(ctx, &fib_params.l, sizeof(fib_params), 0);
	if (ret != 0) {
		ext_err = ret;
		ret = DROP_NO_FIB;
		goto drop_err;
	}

	ret = maybe_add_l2_hdr(ctx, fib_params.l.ifindex, &l2_hdr_required);
	if (ret != 0)
		goto drop_err;
	if (!l2_hdr_required)
		goto out_send;

	if (eth_store_daddr(ctx, fib_params.l.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (eth_store_saddr(ctx, fib_params.l.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
out_send:
	cilium_capture_out(ctx);
	return ctx_redirect(ctx, fib_params.l.ifindex, 0);
drop_err:
	return send_drop_notify_error_ext(ctx, 0, ret, ext_err, CTX_ACT_DROP,
				      dir == NAT_DIR_INGRESS ?
				      METRIC_INGRESS : METRIC_EGRESS);
}

/* Main node-port entry point for host-external ingressing node-port traffic
 * which handles the case of: i) backend is local EP, ii) backend is remote EP,
 * iii) reply from remote backend EP.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_update"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1773,
  "endLine": 1943,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "nodeport_lb4",
  "developer_inline_comments": [
    {
      "start_line": 1769,
      "end_line": 1772,
      "text": "/* Main node-port entry point for host-external ingressing node-port traffic\n * which handles the case of: i) backend is local EP, ii) backend is remote EP,\n * iii) reply from remote backend EP.\n */"
    },
    {
      "start_line": 1842,
      "end_line": 1845,
      "text": "/* The packet is not destined to a service but it can be a reply\n\t\t * packet from a remote backend, in which case we need to perform\n\t\t * the reverse NAT.\n\t\t */"
    },
    {
      "start_line": 1855,
      "end_line": 1857,
      "text": "/* For NAT64 we might see an IPv4 reply from the backend to\n\t\t * the LB entering this path. Thus, transform back to IPv6.\n\t\t */"
    },
    {
      "start_line": 1874,
      "end_line": 1876,
      "text": "/* Reply from DSR packet is never seen on this node again hence no\n\t * need to track in here.\n\t */"
    },
    {
      "start_line": 1896,
      "end_line": 1898,
      "text": "/* Recreate CT entries, as the existing one is stale and\n\t\t\t * belongs to a flow which target a different svc.\n\t\t\t */"
    },
    {
      "start_line": 1931,
      "end_line": 1931,
      "text": "/* DSR_ENCAP_MODE */"
    }
  ],
  "updateMaps": [
    "  NODEPORT_NEIGH4"
  ],
  "readMaps": [
    "  NODEPORT_NEIGH4"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 src_identity"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "map_update_elem",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int nodeport_lb4 (struct  __ctx_buff *ctx, __u32 src_identity)\n",
    "{\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    int ret, l3_off = ETH_HLEN, l4_off;\n",
    "    struct csum_offset csum_off = {}\n",
    "    ;\n",
    "    struct lb4_service *svc;\n",
    "    struct lb4_key key = {}\n",
    "    ;\n",
    "    struct ct_state ct_state_new = {}\n",
    "    ;\n",
    "    union macaddr smac, *mac;\n",
    "    bool backend_local;\n",
    "    __u32 monitor = 0;\n",
    "    cilium_capture_in (ctx);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip4->protocol;\n",
    "    tuple.daddr = ip4->daddr;\n",
    "    tuple.saddr = ip4->saddr;\n",
    "    l4_off = l3_off + ipv4_hdrlen (ip4);\n",
    "    ret = lb4_extract_key (ctx, ip4, l4_off, & key, & csum_off, CT_EGRESS);\n",
    "    if (IS_ERR (ret)) {\n",
    "        if (ret == DROP_NO_SERVICE)\n",
    "            goto skip_service_lookup;\n",
    "        else if (ret == DROP_UNKNOWN_L4)\n",
    "            return CTX_ACT_OK;\n",
    "        else\n",
    "            return ret;\n",
    "    }\n",
    "    svc = lb4_lookup_service (& key, false);\n",
    "    if (svc) {\n",
    "        const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;\n",
    "        if (!lb4_src_range_ok (svc, ip4->saddr))\n",
    "            return DROP_NOT_IN_SRC_RANGE;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "        if (lb4_svc_is_l7loadbalancer (svc) && svc->l7_lb_proxy_port > 0) {\n",
    "            send_trace_notify (ctx, TRACE_TO_PROXY, src_identity, 0, bpf_ntohs ((__u16) svc->l7_lb_proxy_port), 0, TRACE_REASON_POLICY, monitor);\n",
    "            return ctx_redirect_to_proxy_hairpin_ipv4 (ctx, (__be16) svc->l7_lb_proxy_port);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        if (lb4_to_lb6_service (svc)) {\n",
    "            ret = lb4_to_lb6 (ctx, ip4, l3_off);\n",
    "            if (!ret)\n",
    "                return NAT_46X64_RECIRC;\n",
    "        }\n",
    "        else {\n",
    "            ret = lb4_local (get_ct_map4 (& tuple), ctx, l3_off, l4_off, & csum_off, & key, & tuple, svc, & ct_state_new, ip4 -> saddr, ipv4_has_l4_header (ip4), skip_l3_xlate);\n",
    "        }\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (!svc || !lb4_svc_is_routable (svc)) {\n",
    "        if (svc)\n",
    "            return DROP_IS_CLUSTER_IP;\n",
    "    skip_service_lookup :\n",
    "        ctx_set_xfer (ctx, XFER_PKT_NO_SVC);\n",
    "\n",
    "#ifndef ENABLE_MASQUERADE\n",
    "        if (nodeport_uses_dsr4 (&tuple))\n",
    "            return CTX_ACT_OK;\n",
    "\n",
    "#endif\n",
    "        ctx_store_meta (ctx, CB_NAT, NAT_DIR_INGRESS);\n",
    "        ctx_store_meta (ctx, CB_SRC_IDENTITY, src_identity);\n",
    "        if (!lb4_populate_ports (ctx, &tuple, l4_off) && snat_v6_has_v4_match (&tuple)) {\n",
    "            ret = lb4_to_lb6 (ctx, ip4, l3_off);\n",
    "            if (ret)\n",
    "                return ret;\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);\n",
    "        }\n",
    "        else {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);\n",
    "        }\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "    backend_local = __lookup_ip4_endpoint (tuple.daddr);\n",
    "    if (!backend_local && lb4_svc_is_hostport (svc))\n",
    "        return DROP_INVALID;\n",
    "    if (backend_local || !nodeport_uses_dsr4 (&tuple)) {\n",
    "        struct ct_state ct_state = {}\n",
    "        ;\n",
    "        ret = ct_lookup4 (get_ct_map4 (& tuple), & tuple, ctx, l4_off, CT_EGRESS, & ct_state, & monitor);\n",
    "        switch (ret) {\n",
    "        case CT_NEW :\n",
    "        redo :\n",
    "            ct_state_new.src_sec_id = WORLD_ID;\n",
    "            ct_state_new.node_port = 1;\n",
    "            ct_state_new.ifindex = (__u16) NATIVE_DEV_IFINDEX;\n",
    "            ret = ct_create4 (get_ct_map4 (& tuple), NULL, & tuple, ctx, CT_EGRESS, & ct_state_new, false, false);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "            break;\n",
    "        case CT_REOPENED :\n",
    "        case CT_ESTABLISHED :\n",
    "        case CT_REPLY :\n",
    "            if (unlikely (ct_state.rev_nat_index != svc->rev_nat_index))\n",
    "                goto redo;\n",
    "            break;\n",
    "        default :\n",
    "            return DROP_UNKNOWN_CT;\n",
    "        }\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "        if (eth_load_saddr (ctx, smac.addr, 0) < 0)\n",
    "            return DROP_INVALID;\n",
    "        mac = map_lookup_elem (& NODEPORT_NEIGH4, & ip4 -> saddr);\n",
    "        if (!mac || eth_addrcmp (mac, &smac)) {\n",
    "            ret = map_update_elem (& NODEPORT_NEIGH4, & ip4 -> saddr, & smac, 0);\n",
    "            if (ret < 0)\n",
    "                return ret;\n",
    "        }\n",
    "    }\n",
    "    if (!backend_local) {\n",
    "        edt_set_aggregate (ctx, 0);\n",
    "        if (nodeport_uses_dsr4 (&tuple)) {\n",
    "\n",
    "#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "            ctx_store_meta (ctx, CB_HINT, ((__u32) tuple.sport << 16) | tuple.dport);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V4, tuple.daddr);\n",
    "\n",
    "#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE\n",
    "            ctx_store_meta (ctx, CB_PORT, key.dport);\n",
    "            ctx_store_meta (ctx, CB_ADDR_V4, key.address);\n",
    "\n",
    "#endif /* DSR_ENCAP_MODE */\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_NODEPORT_DSR);\n",
    "        }\n",
    "        else {\n",
    "            ctx_store_meta (ctx, CB_NAT, NAT_DIR_EGRESS);\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);\n",
    "        }\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "    ctx_set_xfer (ctx, XFER_PKT_NO_SVC);\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb4_src_range_ok",
    "ctx_set_xfer",
    "bpf_ntohs",
    "lb4_svc_is_l7loadbalancer",
    "nodeport_uses_dsr4",
    "lb4_lookup_service",
    "lb4_to_lb6_service",
    "snat_v6_has_v4_match",
    "cilium_capture_in",
    "ctx_store_meta",
    "ipv4_hdrlen",
    "unlikely",
    "eth_addrcmp",
    "ct_lookup4",
    "lb4_local",
    "edt_set_aggregate",
    "ipv4_has_l4_header",
    "lb4_extract_key",
    "ep_tail_call",
    "__lookup_ip4_endpoint",
    "ct_create4",
    "send_trace_notify",
    "lb4_to_lb6",
    "revalidate_data",
    "eth_load_saddr",
    "ctx_redirect_to_proxy_hairpin_ipv4",
    "lb4_svc_is_routable",
    "defined",
    "lb4_populate_ports",
    "get_ct_map4",
    "IS_ERR",
    "lb4_svc_is_hostport"
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
static __always_inline int nodeport_lb4(struct __ctx_buff *ctx,
					__u32 src_identity)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	int ret,  l3_off = ETH_HLEN, l4_off;
	struct csum_offset csum_off = {};
	struct lb4_service *svc;
	struct lb4_key key = {};
	struct ct_state ct_state_new = {};
	union macaddr smac, *mac;
	bool backend_local;
	__u32 monitor = 0;

	cilium_capture_in(ctx);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);

	ret = lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off, CT_EGRESS);
	if (IS_ERR(ret)) {
		if (ret == DROP_NO_SERVICE)
			goto skip_service_lookup;
		else if (ret == DROP_UNKNOWN_L4)
			return CTX_ACT_OK;
		else
			return ret;
	}

	svc = lb4_lookup_service(&key, false);
	if (svc) {
		const bool skip_l3_xlate = DSR_ENCAP_MODE == DSR_ENCAP_IPIP;

		if (!lb4_src_range_ok(svc, ip4->saddr))
			return DROP_NOT_IN_SRC_RANGE;
#if defined(ENABLE_L7_LB)
		if (lb4_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
			send_trace_notify(ctx, TRACE_TO_PROXY, src_identity, 0,
					  bpf_ntohs((__u16)svc->l7_lb_proxy_port), 0,
					  TRACE_REASON_POLICY, monitor);
			return ctx_redirect_to_proxy_hairpin_ipv4(ctx,
								  (__be16)svc->l7_lb_proxy_port);
		}
#endif
		if (lb4_to_lb6_service(svc)) {
			ret = lb4_to_lb6(ctx, ip4, l3_off);
			if (!ret)
				return NAT_46X64_RECIRC;
		} else {
			ret = lb4_local(get_ct_map4(&tuple), ctx, l3_off, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					ip4->saddr, ipv4_has_l4_header(ip4),
					skip_l3_xlate);
		}
		if (IS_ERR(ret))
			return ret;
	}

	if (!svc || !lb4_svc_is_routable(svc)) {
		if (svc)
			return DROP_IS_CLUSTER_IP;

		/* The packet is not destined to a service but it can be a reply
		 * packet from a remote backend, in which case we need to perform
		 * the reverse NAT.
		 */
skip_service_lookup:
		ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

#ifndef ENABLE_MASQUERADE
		if (nodeport_uses_dsr4(&tuple))
			return CTX_ACT_OK;
#endif
		ctx_store_meta(ctx, CB_NAT, NAT_DIR_INGRESS);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, src_identity);
		/* For NAT64 we might see an IPv4 reply from the backend to
		 * the LB entering this path. Thus, transform back to IPv6.
		 */
		if (!lb4_populate_ports(ctx, &tuple, l4_off) &&
		    snat_v6_has_v4_match(&tuple)) {
			ret = lb4_to_lb6(ctx, ip4, l3_off);
			if (ret)
				return ret;
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_NAT);
		} else {
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	backend_local = __lookup_ip4_endpoint(tuple.daddr);
	if (!backend_local && lb4_svc_is_hostport(svc))
		return DROP_INVALID;

	/* Reply from DSR packet is never seen on this node again hence no
	 * need to track in here.
	 */
	if (backend_local || !nodeport_uses_dsr4(&tuple)) {
		struct ct_state ct_state = {};

		ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off,
				 CT_EGRESS, &ct_state, &monitor);
		switch (ret) {
		case CT_NEW:
redo:
			ct_state_new.src_sec_id = WORLD_ID;
			ct_state_new.node_port = 1;
			ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
			ret = ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
					 CT_EGRESS, &ct_state_new, false, false);
			if (IS_ERR(ret))
				return ret;
			break;
		case CT_REOPENED:
		case CT_ESTABLISHED:
		case CT_REPLY:
			/* Recreate CT entries, as the existing one is stale and
			 * belongs to a flow which target a different svc.
			 */
			if (unlikely(ct_state.rev_nat_index !=
				     svc->rev_nat_index))
				goto redo;
			break;
		default:
			return DROP_UNKNOWN_CT;
		}

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		if (eth_load_saddr(ctx, smac.addr, 0) < 0)
			return DROP_INVALID;

		mac = map_lookup_elem(&NODEPORT_NEIGH4, &ip4->saddr);
		if (!mac || eth_addrcmp(mac, &smac)) {
			ret = map_update_elem(&NODEPORT_NEIGH4, &ip4->saddr,
					      &smac, 0);
			if (ret < 0)
				return ret;
		}
	}

	if (!backend_local) {
		edt_set_aggregate(ctx, 0);
		if (nodeport_uses_dsr4(&tuple)) {
#if DSR_ENCAP_MODE == DSR_ENCAP_IPIP
			ctx_store_meta(ctx, CB_HINT,
				       ((__u32)tuple.sport << 16) | tuple.dport);
			ctx_store_meta(ctx, CB_ADDR_V4, tuple.daddr);
#elif DSR_ENCAP_MODE == DSR_ENCAP_NONE
			ctx_store_meta(ctx, CB_PORT, key.dport);
			ctx_store_meta(ctx, CB_ADDR_V4, key.address);
#endif /* DSR_ENCAP_MODE */
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_DSR);
		} else {
			ctx_store_meta(ctx, CB_NAT, NAT_DIR_EGRESS);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_NAT);
		}
		return DROP_MISSED_TAIL_CALL;
	}

	ctx_set_xfer(ctx, XFER_PKT_NO_SVC);

	return CTX_ACT_OK;
}

/* Reverse NAT handling of node-port traffic for the case where the
 * backend i) was a local EP and bpf_lxc redirected to us, ii) was
 * a remote backend and we got here after reverse SNAT from the
 * tail_nodeport_nat_ipv4().
 *
 * Also, reverse NAT handling return path egress-gw traffic.
 *
 * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS
 * of the bpf_host, bpf_overlay and of the bpf_lxc.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Do FIB lookup in kernel tables using parameters in params. If lookup is successful and result shows packet is to be forwarded , the neighbor tables are searched for the nexthop. If successful (ie. , FIB lookup shows forwarding and nexthop is resolved) , the nexthop address is returned in ipv4_dst or ipv6_dst based on family , smac is set to mac address of egress device , dmac is set to nexthop mac address , rt_metric is set to metric from route (IPv4/IPv6 only) , and ifindex is set to the device index of the nexthop from the FIB lookup. <[ plen ]>(IP: 2) argument is the size of the passed in struct. <[ flags ]>(IP: 3) argument can be a combination of one or more of the following values: BPF_FIB_LOOKUP_DIRECT Do a direct table lookup vs full lookup using FIB rules. BPF_FIB_LOOKUP_OUTPUT Perform lookup from an egress perspective (default is ingress). <[ ctx ]>(IP: 0) is either struct xdp_md for XDP programs or struct sk_buff tc cls_act programs. Return \u00b7 < 0 if any input argument is invalid \u00b7 0 on success (packet is forwarded , nexthop neighbor exists) \u00b7 > 0 one of BPF_FIB_LKUP_RET_ codes explaining why the packet is not forwarded or needs assist from full stack ",
          "Function Name": "bpf_fib_lookup",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct bpf_fib_lookup ,Var: *params}",
            "{Type:  int ,Var: plen}",
            "{Type:  u32 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1955,
  "endLine": 2126,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "rev_nodeport_lb4",
  "developer_inline_comments": [
    {
      "start_line": 1945,
      "end_line": 1954,
      "text": "/* Reverse NAT handling of node-port traffic for the case where the\n * backend i) was a local EP and bpf_lxc redirected to us, ii) was\n * a remote backend and we got here after reverse SNAT from the\n * tail_nodeport_nat_ipv4().\n *\n * Also, reverse NAT handling return path egress-gw traffic.\n *\n * CILIUM_CALL_IPV{4,6}_NODEPORT_REVNAT is plugged into CILIUM_MAP_CALLS\n * of the bpf_host, bpf_overlay and of the bpf_lxc.\n */"
    },
    {
      "start_line": 1982,
      "end_line": 1994,
      "text": "/* Traffic from clients to egress gateway nodes reaches said gateways\n\t * by a vxlan tunnel. If we are not using TUNNEL_MODE, we need to\n\t * identify reverse traffic from the gateway to clients and also steer\n\t * it via the vxlan tunnel to avoid issues with iptables dropping these\n\t * packets. We do this in the code below, by performing a lookup in the\n\t * egress gateway map using a reverse address tuple. A match means that\n\t * the corresponding forward traffic was forwarded to the egress gateway\n\t * via the tunnel.\n\t *\n\t * Currently, we don't support redirect to a tunnel netdev / encap on\n\t * XDP. Thus, the problem mentioned above is present when using the\n\t * egress gw feature with bpf_xdp.\n\t */"
    },
    {
      "start_line": 2009,
      "end_line": 2009,
      "text": "/* ENABLE_EGRESS_GATEWAY */"
    },
    {
      "start_line": 2048,
      "end_line": 2054,
      "text": "/* If the FIB lookup was successful, use the outgoing\n\t\t\t * iface from its result. Otherwise, we will fallback\n\t\t\t * to CT's ifindex which was learned when the request\n\t\t\t * was sent. The latter assumes that the reply should\n\t\t\t * be sent over the same device which received the\n\t\t\t * request.\n\t\t\t */"
    },
    {
      "start_line": 2073,
      "end_line": 2082,
      "text": "/* For the case where a client from the same L2\n\t\t\t * domain previously sent traffic over the node\n\t\t\t * which did the service -> backend translation\n\t\t\t * and that node has never seen the client before\n\t\t\t * then XDP/tc BPF layer won't create a neighbor\n\t\t\t * entry for it. This makes the above fib_lookup()\n\t\t\t * fail and we have to consult the NODEPORT_NEIGH4\n\t\t\t * table instead where we recorded the client\n\t\t\t * address in nodeport_lb4().\n\t\t\t */"
    },
    {
      "start_line": 2118,
      "end_line": 2118,
      "text": "/* fib lookup not necessary when going over tunnel. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  NODEPORT_NEIGH4"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int *ifindex",
    " int *ext_err"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "fib_lookup",
    "CTX_ACT_OK",
    "bpf_fib_lookup",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int rev_nodeport_lb4 (struct  __ctx_buff *ctx, int *ifindex, int *ext_err)\n",
    "{\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    struct csum_offset csum_off = {}\n",
    "    ;\n",
    "    int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off;\n",
    "    struct ct_state ct_state = {}\n",
    "    ;\n",
    "    struct bpf_fib_lookup fib_params = {}\n",
    "    ;\n",
    "    enum trace_reason __maybe_unused reason = TRACE_REASON_UNKNOWN;\n",
    "    __u32 monitor = TRACE_PAYLOAD_LEN;\n",
    "    bool l2_hdr_required = true;\n",
    "    __u32 tunnel_endpoint __maybe_unused = 0;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip4->protocol;\n",
    "    tuple.daddr = ip4->daddr;\n",
    "    tuple.saddr = ip4->saddr;\n",
    "    l4_off = l3_off + ipv4_hdrlen (ip4);\n",
    "    csum_l4_offset_and_flags (tuple.nexthdr, &csum_off);\n",
    "\n",
    "#if defined(ENABLE_EGRESS_GATEWAY) && !defined(TUNNEL_MODE) && \\\n",
    "\t__ctx_is != __ctx_xdp\n",
    "    {\n",
    "        struct egress_gw_policy_entry *egress_policy;\n",
    "        egress_policy = lookup_ip4_egress_gw_policy (ip4 -> daddr, ip4 -> saddr);\n",
    "        if (egress_policy) {\n",
    "            struct remote_endpoint_info *info;\n",
    "            info = ipcache_lookup4 (& IPCACHE_MAP, ip4 -> daddr, V4_CACHE_KEY_LEN);\n",
    "            if (info && info->tunnel_endpoint != 0) {\n",
    "                tunnel_endpoint = info->tunnel_endpoint;\n",
    "                goto encap_redirect;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_EGRESS_GATEWAY */\n",
    "    ret = ct_lookup4 (get_ct_map4 (& tuple), & tuple, ctx, l4_off, CT_INGRESS, & ct_state, & monitor);\n",
    "    if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {\n",
    "        reason = TRACE_REASON_CT_REPLY;\n",
    "        ret2 = lb4_rev_nat (ctx, l3_off, l4_off, & csum_off, & ct_state, & tuple, REV_NAT_F_TUPLE_SADDR, ipv4_has_l4_header (ip4));\n",
    "        if (IS_ERR (ret2))\n",
    "            return ret2;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "        bpf_mark_snat_done (ctx);\n",
    "        *ifindex = ct_state.ifindex;\n",
    "\n",
    "#if defined(TUNNEL_MODE) && __ctx_is != __ctx_xdp\n",
    "        {\n",
    "            struct remote_endpoint_info *info;\n",
    "            info = ipcache_lookup4 (& IPCACHE_MAP, ip4 -> daddr, V4_CACHE_KEY_LEN);\n",
    "            if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "                tunnel_endpoint = info->tunnel_endpoint;\n",
    "                goto encap_redirect;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        fib_params.family = AF_INET;\n",
    "        fib_params.ifindex = ctx_get_ifindex (ctx);\n",
    "        fib_params.ipv4_src = ip4->saddr;\n",
    "        fib_params.ipv4_dst = ip4->daddr;\n",
    "        fib_ret = fib_lookup (ctx, & fib_params, sizeof (fib_params), 0);\n",
    "        if (fib_ret == 0)\n",
    "            *ifindex = fib_params.ifindex;\n",
    "        ret = maybe_add_l2_hdr (ctx, * ifindex, & l2_hdr_required);\n",
    "        if (ret != 0)\n",
    "            return ret;\n",
    "        if (!l2_hdr_required)\n",
    "            return CTX_ACT_OK;\n",
    "        if (fib_ret != 0) {\n",
    "            union macaddr smac = NATIVE_DEV_MAC_BY_IFINDEX (* ifindex);\n",
    "            union macaddr *dmac;\n",
    "            if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH) {\n",
    "                *ext_err = fib_ret;\n",
    "                return DROP_NO_FIB;\n",
    "            }\n",
    "            dmac = map_lookup_elem (& NODEPORT_NEIGH4, & tuple.daddr);\n",
    "            if (unlikely (!dmac)) {\n",
    "                *ext_err = fib_ret;\n",
    "                return DROP_NO_FIB;\n",
    "            }\n",
    "            if (eth_store_daddr_aligned (ctx, dmac->addr, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "            if (eth_store_saddr_aligned (ctx, smac.addr, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "        }\n",
    "        else {\n",
    "            if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "            if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if (!bpf_skip_recirculation (ctx)) {\n",
    "            bpf_skip_nodeport_set (ctx);\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_NETDEV);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
    "\n",
    "#if (defined(ENABLE_EGRESS_GATEWAY) || defined(TUNNEL_MODE)) && \\\n",
    "\t__ctx_is != __ctx_xdp\n",
    "encap_redirect :\n",
    "    ret = __encap_with_nodeid (ctx, tunnel_endpoint, SECLABEL, NOT_VTEP_DST, reason, monitor);\n",
    "    if (ret)\n",
    "        return ret;\n",
    "    *ifindex = ENCAP_IFINDEX;\n",
    "    if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return CTX_ACT_OK;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_skip_nodeport_set",
    "ipv4_hdrlen",
    "NATIVE_DEV_MAC_BY_IFINDEX",
    "unlikely",
    "ct_lookup4",
    "ipv4_has_l4_header",
    "maybe_add_l2_hdr",
    "ep_tail_call",
    "eth_store_daddr",
    "eth_store_saddr_aligned",
    "revalidate_data",
    "lookup_ip4_egress_gw_policy",
    "bpf_mark_snat_done",
    "__encap_with_nodeid",
    "defined",
    "ipcache_lookup4",
    "get_ct_map4",
    "lb4_rev_nat",
    "ctx_get_ifindex",
    "IS_ERR",
    "bpf_skip_recirculation",
    "eth_store_daddr_aligned",
    "eth_store_saddr",
    "csum_l4_offset_and_flags"
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
static __always_inline int rev_nodeport_lb4(struct __ctx_buff *ctx, int *ifindex,
					    int *ext_err)
{
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct csum_offset csum_off = {};
	int ret, fib_ret, ret2, l3_off = ETH_HLEN, l4_off;
	struct ct_state ct_state = {};
	struct bpf_fib_lookup fib_params = {};
	enum trace_reason __maybe_unused reason = TRACE_REASON_UNKNOWN;
	__u32 monitor = TRACE_PAYLOAD_LEN;
	bool l2_hdr_required = true;
	__u32 tunnel_endpoint __maybe_unused = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;

	l4_off = l3_off + ipv4_hdrlen(ip4);
	csum_l4_offset_and_flags(tuple.nexthdr, &csum_off);

#if defined(ENABLE_EGRESS_GATEWAY) && !defined(TUNNEL_MODE) && \
	__ctx_is != __ctx_xdp
	/* Traffic from clients to egress gateway nodes reaches said gateways
	 * by a vxlan tunnel. If we are not using TUNNEL_MODE, we need to
	 * identify reverse traffic from the gateway to clients and also steer
	 * it via the vxlan tunnel to avoid issues with iptables dropping these
	 * packets. We do this in the code below, by performing a lookup in the
	 * egress gateway map using a reverse address tuple. A match means that
	 * the corresponding forward traffic was forwarded to the egress gateway
	 * via the tunnel.
	 *
	 * Currently, we don't support redirect to a tunnel netdev / encap on
	 * XDP. Thus, the problem mentioned above is present when using the
	 * egress gw feature with bpf_xdp.
	 */
	{
		struct egress_gw_policy_entry *egress_policy;

		egress_policy = lookup_ip4_egress_gw_policy(ip4->daddr, ip4->saddr);
		if (egress_policy) {
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				goto encap_redirect;
			}
		}
	}
#endif /* ENABLE_EGRESS_GATEWAY */
	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, l4_off, CT_INGRESS, &ct_state,
			 &monitor);

	if (ret == CT_REPLY && ct_state.node_port == 1 && ct_state.rev_nat_index != 0) {
		reason = TRACE_REASON_CT_REPLY;
		ret2 = lb4_rev_nat(ctx, l3_off, l4_off, &csum_off,
				   &ct_state, &tuple,
				   REV_NAT_F_TUPLE_SADDR, ipv4_has_l4_header(ip4));
		if (IS_ERR(ret2))
			return ret2;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		bpf_mark_snat_done(ctx);

		*ifindex = ct_state.ifindex;
#if defined(TUNNEL_MODE) && __ctx_is != __ctx_xdp
		{
			struct remote_endpoint_info *info;

			info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
			if (info != NULL && info->tunnel_endpoint != 0) {
				tunnel_endpoint = info->tunnel_endpoint;
				goto encap_redirect;
			}
		}
#endif

		fib_params.family = AF_INET;
		fib_params.ifindex = ctx_get_ifindex(ctx);

		fib_params.ipv4_src = ip4->saddr;
		fib_params.ipv4_dst = ip4->daddr;

		fib_ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

		if (fib_ret == 0)
			/* If the FIB lookup was successful, use the outgoing
			 * iface from its result. Otherwise, we will fallback
			 * to CT's ifindex which was learned when the request
			 * was sent. The latter assumes that the reply should
			 * be sent over the same device which received the
			 * request.
			 */
			*ifindex = fib_params.ifindex;

		ret = maybe_add_l2_hdr(ctx, *ifindex, &l2_hdr_required);
		if (ret != 0)
			return ret;
		if (!l2_hdr_required)
			return CTX_ACT_OK;

		if (fib_ret != 0) {
			union macaddr smac =
				NATIVE_DEV_MAC_BY_IFINDEX(*ifindex);
			union macaddr *dmac;

			if (fib_ret != BPF_FIB_LKUP_RET_NO_NEIGH) {
				*ext_err = fib_ret;
				return DROP_NO_FIB;
			}

			/* For the case where a client from the same L2
			 * domain previously sent traffic over the node
			 * which did the service -> backend translation
			 * and that node has never seen the client before
			 * then XDP/tc BPF layer won't create a neighbor
			 * entry for it. This makes the above fib_lookup()
			 * fail and we have to consult the NODEPORT_NEIGH4
			 * table instead where we recorded the client
			 * address in nodeport_lb4().
			 */
			dmac = map_lookup_elem(&NODEPORT_NEIGH4, &tuple.daddr);
			if (unlikely(!dmac)) {
				*ext_err = fib_ret;
				return DROP_NO_FIB;
			}
			if (eth_store_daddr_aligned(ctx, dmac->addr, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr_aligned(ctx, smac.addr, 0) < 0)
				return DROP_WRITE_ERROR;
		} else {
			if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
				return DROP_WRITE_ERROR;
			if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
				return DROP_WRITE_ERROR;
		}
	} else {
		if (!bpf_skip_recirculation(ctx)) {
			bpf_skip_nodeport_set(ctx);
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
			return DROP_MISSED_TAIL_CALL;
		}
	}

	return CTX_ACT_OK;

#if (defined(ENABLE_EGRESS_GATEWAY) || defined(TUNNEL_MODE)) && \
	__ctx_is != __ctx_xdp
encap_redirect:
	ret = __encap_with_nodeid(ctx, tunnel_endpoint, SECLABEL, NOT_VTEP_DST,
				  reason, monitor);
	if (ret)
		return ret;

	*ifindex = ENCAP_IFINDEX;

	/* fib lookup not necessary when going over tunnel. */
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
#endif
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_NODEPORT_REVNAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2129,
  "endLine": 2162,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_rev_nodeport_lb4",
  "developer_inline_comments": [
    {
      "start_line": 2135,
      "end_line": 2137,
      "text": "/* We only enforce the host policies if nodeport.h is included from\n\t * bpf_host.\n\t */"
    },
    {
      "start_line": 2148,
      "end_line": 2150,
      "text": "/* We don't want to enforce host policies a second time if we jump back to\n\t * bpf_host's handle_ipv6.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_rev_nodeport_lb4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ifindex = 0;\n",
    "    int ext_err = 0;\n",
    "    int ret = 0;\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u32 src_id = 0;\n",
    "    ret = ipv4_host_policy_ingress (ctx, & src_id, & trace);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    ctx_skip_host_fw_set (ctx);\n",
    "\n",
    "#endif\n",
    "    ret = rev_nodeport_lb4 (ctx, & ifindex, & ext_err);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error_ext (ctx, 0, ret, ext_err, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "    edt_set_aggregate (ctx, 0);\n",
    "    cilium_capture_out (ctx);\n",
    "    return ctx_redirect (ctx, ifindex, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "edt_set_aggregate",
    "cilium_capture_out",
    "defined",
    "rev_nodeport_lb4",
    "IS_ERR",
    "ctx_redirect",
    "ctx_skip_host_fw_set",
    "send_drop_notify_error",
    "send_drop_notify_error_ext",
    "ipv4_host_policy_ingress"
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
int tail_rev_nodeport_lb4(struct __ctx_buff *ctx)
{
	int ifindex = 0;
	int ext_err = 0;
	int ret = 0;
#if defined(ENABLE_HOST_FIREWALL) && defined(IS_BPF_HOST)
	/* We only enforce the host policies if nodeport.h is included from
	 * bpf_host.
	 */
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	/* We don't want to enforce host policies a second time if we jump back to
	 * bpf_host's handle_ipv6.
	 */
	ctx_skip_host_fw_set(ctx);
#endif
	ret = rev_nodeport_lb4(ctx, &ifindex, &ext_err);
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(ctx, 0, ret, ext_err,
						  CTX_ACT_DROP, METRIC_EGRESS);

	edt_set_aggregate(ctx, 0);
	cilium_capture_out(ctx);

	return ctx_redirect(ctx, ifindex, 0);
}

declare_tailcall_if(__or3(__and(is_defined(ENABLE_IPV4),
				is_defined(ENABLE_IPV6)),
			  __and(is_defined(ENABLE_HOST_FIREWALL),
				is_defined(IS_BPF_HOST)),
			  is_defined(ENABLE_EGRESS_GATEWAY)),
		    CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2170,
  "endLine": 2188,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "tail_handle_nat_fwd_ipv4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_handle_nat_fwd_ipv4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret;\n",
    "    enum trace_point obs_point;\n",
    "\n",
    "#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)\n",
    "    obs_point = TRACE_TO_OVERLAY;\n",
    "\n",
    "#else\n",
    "    obs_point = TRACE_TO_NETWORK;\n",
    "\n",
    "#endif\n",
    "    ret = nodeport_nat_ipv4_fwd (ctx);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "    send_trace_notify (ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "nodeport_nat_ipv4_fwd",
    "send_trace_notify",
    "IS_ERR",
    "send_drop_notify_error"
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
int tail_handle_nat_fwd_ipv4(struct __ctx_buff *ctx)
{
	int ret;
	enum trace_point obs_point;

#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	obs_point = TRACE_TO_OVERLAY;
#else
	obs_point = TRACE_TO_NETWORK;
#endif

	ret = nodeport_nat_ipv4_fwd(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);

	send_trace_notify(ctx, obs_point, 0, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);

	return ret;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_HEALTH_CHECK
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2192,
  "endLine": 2211,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "health_encap_v4",
  "developer_inline_comments": [
    {
      "start_line": 2198,
      "end_line": 2201,
      "text": "/* When encapsulating, a packet originating from the local\n\t * host is being considered as a packet from a remote node\n\t * as it is being received.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 tunnel_ep",
    " __u32 seclabel"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int health_encap_v4 (struct  __ctx_buff *ctx, __u32 tunnel_ep, __u32 seclabel)\n",
    "{\n",
    "    struct bpf_tunnel_key key;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;\n",
    "    key.remote_ipv4 = bpf_htonl (tunnel_ep);\n",
    "    key.tunnel_ttl = 64;\n",
    "    if (unlikely (ctx_set_tunnel_key (ctx, &key, sizeof (key), BPF_F_ZERO_CSUM_TX) < 0))\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "unlikely",
    "memset",
    "ctx_set_tunnel_key",
    "bpf_htonl"
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
static __always_inline int
health_encap_v4(struct __ctx_buff *ctx, __u32 tunnel_ep,
		__u32 seclabel)
{
	struct bpf_tunnel_key key;

	/* When encapsulating, a packet originating from the local
	 * host is being considered as a packet from a remote node
	 * as it is being received.
	 */
	memset(&key, 0, sizeof(key));
	key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;
	key.remote_ipv4 = bpf_htonl(tunnel_ep);
	key.tunnel_ttl = 64;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, sizeof(key),
					BPF_F_ZERO_CSUM_TX) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2213,
  "endLine": 2232,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "health_encap_v6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *tunnel_ep",
    " __u32 seclabel"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int health_encap_v6 (struct  __ctx_buff *ctx, const union v6addr *tunnel_ep, __u32 seclabel)\n",
    "{\n",
    "    struct bpf_tunnel_key key;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;\n",
    "    key.remote_ipv6[0] = tunnel_ep->p1;\n",
    "    key.remote_ipv6[1] = tunnel_ep->p2;\n",
    "    key.remote_ipv6[2] = tunnel_ep->p3;\n",
    "    key.remote_ipv6[3] = tunnel_ep->p4;\n",
    "    key.tunnel_ttl = 64;\n",
    "    if (unlikely (ctx_set_tunnel_key (ctx, &key, sizeof (key), BPF_F_ZERO_CSUM_TX | BPF_F_TUNINFO_IPV6) < 0))\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "memset",
    "ctx_set_tunnel_key",
    "unlikely"
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
static __always_inline int
health_encap_v6(struct __ctx_buff *ctx, const union v6addr *tunnel_ep,
		__u32 seclabel)
{
	struct bpf_tunnel_key key;

	memset(&key, 0, sizeof(key));
	key.tunnel_id = seclabel == HOST_ID ? LOCAL_NODE_ID : seclabel;
	key.remote_ipv6[0] = tunnel_ep->p1;
	key.remote_ipv6[1] = tunnel_ep->p2;
	key.remote_ipv6[2] = tunnel_ep->p3;
	key.remote_ipv6[3] = tunnel_ep->p4;
	key.tunnel_ttl = 64;

	if (unlikely(ctx_set_tunnel_key(ctx, &key, sizeof(key),
					BPF_F_ZERO_CSUM_TX |
					BPF_F_TUNINFO_IPV6) < 0))
		return DROP_WRITE_ERROR;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "u64",
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "sched_cls",
            "sched_act",
            "cgroup_skb",
            "sock_ops",
            "sk_skb",
            "cgroup_sock_addr"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 2234,
  "endLine": 2280,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "lb_handle_health",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  LB4_HEALTH_MAP",
    "  LB6_HEALTH_MAP"
  ],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "get_socket_cookie",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline int lb_handle_health (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    void * data __maybe_unused, * data_end __maybe_unused;\n",
    "    __sock_cookie key __maybe_unused;\n",
    "    int ret __maybe_unused;\n",
    "    __u16 proto = 0;\n",
    "    if ((ctx->mark & MARK_MAGIC_HEALTH_IPIP_DONE) == MARK_MAGIC_HEALTH_IPIP_DONE)\n",
    "        return CTX_ACT_OK;\n",
    "    validate_ethertype (ctx, &proto);\n",
    "    switch (proto) {\n",
    "\n",
    "#if defined(ENABLE_IPV4) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        {\n",
    "            struct lb4_health *val;\n",
    "            key = get_socket_cookie (ctx);\n",
    "            val = map_lookup_elem (& LB4_HEALTH_MAP, & key);\n",
    "            if (!val)\n",
    "                return CTX_ACT_OK;\n",
    "            ret = health_encap_v4 (ctx, val -> peer.address, 0);\n",
    "            if (ret != 0)\n",
    "                return ret;\n",
    "            ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;\n",
    "            return ctx_redirect (ctx, ENCAP4_IFINDEX, 0);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "\n",
    "#if defined(ENABLE_IPV6) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        {\n",
    "            struct lb6_health *val;\n",
    "            key = get_socket_cookie (ctx);\n",
    "            val = map_lookup_elem (& LB6_HEALTH_MAP, & key);\n",
    "            if (!val)\n",
    "                return CTX_ACT_OK;\n",
    "            ret = health_encap_v6 (ctx, & val -> peer.address, 0);\n",
    "            if (ret != 0)\n",
    "                return ret;\n",
    "            ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;\n",
    "            return ctx_redirect (ctx, ENCAP6_IFINDEX, 0);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "    default :\n",
    "        return CTX_ACT_OK;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "health_encap_v4",
    "health_encap_v6",
    "validate_ethertype",
    "ctx_redirect",
    "bpf_htons"
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
static __always_inline int
lb_handle_health(struct __ctx_buff *ctx __maybe_unused)
{
	void *data __maybe_unused, *data_end __maybe_unused;
	__sock_cookie key __maybe_unused;
	int ret __maybe_unused;
	__u16 proto = 0;

	if ((ctx->mark & MARK_MAGIC_HEALTH_IPIP_DONE) ==
	    MARK_MAGIC_HEALTH_IPIP_DONE)
		return CTX_ACT_OK;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#if defined(ENABLE_IPV4) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IP): {
		struct lb4_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v4(ctx, val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP4_IFINDEX, 0);
	}
#endif
#if defined(ENABLE_IPV6) && DSR_ENCAP_MODE == DSR_ENCAP_IPIP
	case bpf_htons(ETH_P_IPV6): {
		struct lb6_health *val;

		key = get_socket_cookie(ctx);
		val = map_lookup_elem(&LB6_HEALTH_MAP, &key);
		if (!val)
			return CTX_ACT_OK;
		ret = health_encap_v6(ctx, &val->peer.address, 0);
		if (ret != 0)
			return ret;
		ctx->mark |= MARK_MAGIC_HEALTH_IPIP_DONE;
		return ctx_redirect(ctx, ENCAP6_IFINDEX, 0);
	}
#endif
	default:
		return CTX_ACT_OK;
	}
}
#endif /* ENABLE_HEALTH_CHECK */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 2283,
  "endLine": 2319,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nodeport.h",
  "funcName": "handle_nat_fwd",
  "developer_inline_comments": [
    {
      "start_line": 2301,
      "end_line": 2301,
      "text": "/* ENABLE_IPV4 */"
    },
    {
      "start_line": 2311,
      "end_line": 2311,
      "text": "/* ENABLE_IPV6 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int handle_nat_fwd (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return CTX_ACT_OK;\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        invoke_tailcall_if (__or3 (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), __and (is_defined (ENABLE_HOST_FIREWALL), is_defined (IS_BPF_HOST)), is_defined (ENABLE_EGRESS_GATEWAY)), CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT, tail_handle_nat_fwd_ipv4);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        invoke_tailcall_if (__or (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), __and (is_defined (ENABLE_HOST_FIREWALL), is_defined (IS_BPF_HOST))), CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT, tail_handle_nat_fwd_ipv6);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "    default :\n",
    "        build_bug_on (!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));\n",
    "        build_bug_on (!(NODEPORT_PORT_MIN < NODEPORT_PORT_MAX));\n",
    "        build_bug_on (!(NODEPORT_PORT_MAX < NODEPORT_PORT_MIN_NAT));\n",
    "        break;\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "invoke_tailcall_if",
    "__and",
    "build_bug_on",
    "__or3",
    "validate_ethertype",
    "__or",
    "is_defined",
    "bpf_htons"
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
static __always_inline int handle_nat_fwd(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or3(__and(is_defined(ENABLE_IPV4),
					       is_defined(ENABLE_IPV6)),
					 __and(is_defined(ENABLE_HOST_FIREWALL),
					       is_defined(IS_BPF_HOST)),
					 is_defined(ENABLE_EGRESS_GATEWAY)),
				   CILIUM_CALL_IPV4_ENCAP_NODEPORT_NAT,
				   tail_handle_nat_fwd_ipv4);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					__and(is_defined(ENABLE_HOST_FIREWALL),
					      is_defined(IS_BPF_HOST))),
				   CILIUM_CALL_IPV6_ENCAP_NODEPORT_NAT,
				   tail_handle_nat_fwd_ipv6);
		break;
#endif /* ENABLE_IPV6 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN     < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX     < NODEPORT_PORT_MIN_NAT));
		break;
	}
	return ret;
}

#endif /* ENABLE_NODEPORT */
#endif /* __NODEPORT_H_ */
