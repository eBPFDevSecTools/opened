/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IDENTITY_H_
#define __LIB_IDENTITY_H_

#include "dbg.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 12,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "identity_in_range",
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
    "__u32 identity",
    " __u32 range_start",
    " __u32 range_end"
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
    "static __always_inline bool identity_in_range (__u32 identity, __u32 range_start, __u32 range_end)\n",
    "{\n",
    "    return range_start <= identity && identity <= range_end;\n",
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
static __always_inline bool identity_in_range(__u32 identity, __u32 range_start, __u32 range_end)
{
	return range_start <= identity && identity <= range_end;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 32,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "identity_is_remote_node",
  "developer_inline_comments": [
    {
      "start_line": 16,
      "end_line": 30,
      "text": "/* KUBE_APISERVER_NODE_ID is the reserved identity that corresponds to\n\t * the labels 'reserved:remote-node' and 'reserved:kube-apiserver'. As\n\t * such, if it is ever used for determining the identity of a node in\n\t * the cluster, then routing decisions and so on should be made the\n\t * same way as for REMOTE_NODE_ID. If we ever assign unique identities\n\t * to each node in the cluster, then we'll probably need to convert\n\t * the implementation here into a map to select any of the possible\n\t * identities. But for now, this is good enough to capture the notion\n\t * of 'remote nodes in the cluster' for routing decisions.\n\t *\n\t * Note that kube-apiserver policy is handled entirely separately by\n\t * the standard policymap enforcement logic and has no relationship to\n\t * the identity as used here. If the apiserver is outside the cluster,\n\t * then the KUBE_APISERVER_NODE_ID case should not ever be hit.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 identity"
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
    "static __always_inline bool identity_is_remote_node (__u32 identity)\n",
    "{\n",
    "    return identity == REMOTE_NODE_ID || identity == KUBE_APISERVER_NODE_ID;\n",
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
static __always_inline bool identity_is_remote_node(__u32 identity)
{
	/* KUBE_APISERVER_NODE_ID is the reserved identity that corresponds to
	 * the labels 'reserved:remote-node' and 'reserved:kube-apiserver'. As
	 * such, if it is ever used for determining the identity of a node in
	 * the cluster, then routing decisions and so on should be made the
	 * same way as for REMOTE_NODE_ID. If we ever assign unique identities
	 * to each node in the cluster, then we'll probably need to convert
	 * the implementation here into a map to select any of the possible
	 * identities. But for now, this is good enough to capture the notion
	 * of 'remote nodes in the cluster' for routing decisions.
	 *
	 * Note that kube-apiserver policy is handled entirely separately by
	 * the standard policymap enforcement logic and has no relationship to
	 * the identity as used here. If the apiserver is outside the cluster,
	 * then the KUBE_APISERVER_NODE_ID case should not ever be hit.
	 */
	return identity == REMOTE_NODE_ID || identity == KUBE_APISERVER_NODE_ID;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 34,
  "endLine": 37,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "identity_is_node",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 identity"
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
    "static __always_inline bool identity_is_node (__u32 identity)\n",
    "{\n",
    "    return identity == HOST_ID || identity_is_remote_node (identity);\n",
    "}\n"
  ],
  "called_function_list": [
    "identity_is_remote_node"
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
static __always_inline bool identity_is_node(__u32 identity)
{
	return identity == HOST_ID || identity_is_remote_node(identity);
}

/**
 * identity_is_reserved is used to determine whether an identity is one of the
 * reserved identities that are not handed out to endpoints.
 *
 * Specifically, it should return true if the identity is one of these:
 * - IdentityUnknown
 * - ReservedIdentityHost
 * - ReservedIdentityWorld
 * - ReservedIdentityRemoteNode
 * - ReservedIdentityKubeAPIServer
 *
 * The following identities are given to endpoints so return false for these:
 * - ReservedIdentityUnmanaged
 * - ReservedIdentityHealth
 * - ReservedIdentityInit
 *
 * Identities 128 and higher are guaranteed to be generated based on user input.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 60,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "identity_is_reserved",
  "developer_inline_comments": [
    {
      "start_line": 39,
      "end_line": 56,
      "text": "/**\n * identity_is_reserved is used to determine whether an identity is one of the\n * reserved identities that are not handed out to endpoints.\n *\n * Specifically, it should return true if the identity is one of these:\n * - IdentityUnknown\n * - ReservedIdentityHost\n * - ReservedIdentityWorld\n * - ReservedIdentityRemoteNode\n * - ReservedIdentityKubeAPIServer\n *\n * The following identities are given to endpoints so return false for these:\n * - ReservedIdentityUnmanaged\n * - ReservedIdentityHealth\n * - ReservedIdentityInit\n *\n * Identities 128 and higher are guaranteed to be generated based on user input.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 identity"
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
    "static __always_inline bool identity_is_reserved (__u32 identity)\n",
    "{\n",
    "    return identity < UNMANAGED_ID || identity_is_remote_node (identity);\n",
    "}\n"
  ],
  "called_function_list": [
    "identity_is_remote_node"
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
static __always_inline bool identity_is_reserved(__u32 identity)
{
	return identity < UNMANAGED_ID || identity_is_remote_node(identity);
}

/**
 * identity_is_cluster is used to determine whether an identity is assigned to
 * an entity inside the cluster.
 *
 * This function will return false for:
 * - ReservedIdentityWorld
 * - an identity in the CIDR range
 *
 * This function will return true for:
 * - ReservedIdentityHost
 * - ReservedIdentityUnmanaged
 * - ReservedIdentityHealth
 * - ReservedIdentityInit
 * - ReservedIdentityRemoteNode
 * - ReservedIdentityKubeAPIServer
 * - ReservedIdentityIngress
 * - all other identifies
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 80,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "identity_is_cluster",
  "developer_inline_comments": [
    {
      "start_line": 62,
      "end_line": 79,
      "text": "/**\n * identity_is_cluster is used to determine whether an identity is assigned to\n * an entity inside the cluster.\n *\n * This function will return false for:\n * - ReservedIdentityWorld\n * - an identity in the CIDR range\n *\n * This function will return true for:\n * - ReservedIdentityHost\n * - ReservedIdentityUnmanaged\n * - ReservedIdentityHealth\n * - ReservedIdentityInit\n * - ReservedIdentityRemoteNode\n * - ReservedIdentityKubeAPIServer\n * - ReservedIdentityIngress\n * - all other identifies\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 identity"
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
    "static __always_inline bool identity_is_cluster (__u32 identity)\n",
    "{\n",
    "    if (identity == WORLD_ID)\n",
    "        return false;\n",
    "    if (identity_in_range (identity, CIDR_IDENTITY_RANGE_START, CIDR_IDENTITY_RANGE_END))\n",
    "        return false;\n",
    "    return true;\n",
    "}\n"
  ],
  "called_function_list": [
    "identity_in_range"
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
static __always_inline bool identity_is_cluster(__u32 identity)
{
	if (identity == WORLD_ID)
		return false;

	if (identity_in_range(identity, CIDR_IDENTITY_RANGE_START,
			      CIDR_IDENTITY_RANGE_END))
		return false;

	return true;
}

#if __ctx_is == __ctx_skb
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 93,
  "endLine": 137,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/identity.h",
  "funcName": "inherit_identity_from_host",
  "developer_inline_comments": [
    {
      "start_line": 97,
      "end_line": 100,
      "text": "/* Packets from the ingress proxy must skip the proxy when the\n\t * destination endpoint evaluates the policy. As the packet would loop\n\t * and/or the connection be reset otherwise.\n\t */"
    },
    {
      "start_line": 104,
      "end_line": 107,
      "text": "/* (Return) packets from the egress proxy must skip the redirection to\n\t * the proxy, as the packet would loop and/or the connection be reset\n\t * otherwise.\n\t */"
    },
    {
      "start_line": 119,
      "end_line": 119,
      "text": "/* endpoint identity, not security identity! */"
    },
    {
      "start_line": 125,
      "end_line": 125,
      "text": "/* Reset packet mark to avoid hitting routing rules again */"
    },
    {
      "start_line": 129,
      "end_line": 131,
      "text": "/* Caller tail calls back to source endpoint egress in this case,\n\t * do not log the (world) identity.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 *identity"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 inherit_identity_from_host (struct  __ctx_buff *ctx, __u32 *identity)\n",
    "{\n",
    "    __u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;\n",
    "    if (magic == MARK_MAGIC_PROXY_INGRESS) {\n",
    "        *identity = get_identity (ctx);\n",
    "        ctx->tc_index |= TC_INDEX_F_SKIP_INGRESS_PROXY;\n",
    "    }\n",
    "    else if (magic == MARK_MAGIC_PROXY_EGRESS) {\n",
    "        *identity = get_identity (ctx);\n",
    "        ctx->tc_index |= TC_INDEX_F_SKIP_EGRESS_PROXY;\n",
    "    }\n",
    "    else if (magic == MARK_MAGIC_IDENTITY) {\n",
    "        *identity = get_identity (ctx);\n",
    "    }\n",
    "    else if (magic == MARK_MAGIC_HOST) {\n",
    "        *identity = HOST_ID;\n",
    "    }\n",
    "    else if (magic == MARK_MAGIC_ENCRYPT) {\n",
    "        *identity = get_identity (ctx);\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    }\n",
    "    else if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {\n",
    "        *identity = get_epid (ctx);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    else {\n",
    "        *identity = WORLD_ID;\n",
    "    }\n",
    "    ctx->mark = 0;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    if (magic != MARK_MAGIC_PROXY_EGRESS_EPID)\n",
    "\n",
    "#endif\n",
    "        cilium_dbg (ctx, DBG_INHERIT_IDENTITY, *identity, 0);\n",
    "    return magic;\n",
    "}\n"
  ],
  "called_function_list": [
    "get_identity",
    "get_epid",
    "defined",
    "cilium_dbg"
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
static __always_inline __u32 inherit_identity_from_host(struct __ctx_buff *ctx, __u32 *identity)
{
	__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

	/* Packets from the ingress proxy must skip the proxy when the
	 * destination endpoint evaluates the policy. As the packet would loop
	 * and/or the connection be reset otherwise.
	 */
	if (magic == MARK_MAGIC_PROXY_INGRESS) {
		*identity = get_identity(ctx);
		ctx->tc_index |= TC_INDEX_F_SKIP_INGRESS_PROXY;
	/* (Return) packets from the egress proxy must skip the redirection to
	 * the proxy, as the packet would loop and/or the connection be reset
	 * otherwise.
	 */
	} else if (magic == MARK_MAGIC_PROXY_EGRESS) {
		*identity = get_identity(ctx);
		ctx->tc_index |= TC_INDEX_F_SKIP_EGRESS_PROXY;
	} else if (magic == MARK_MAGIC_IDENTITY) {
		*identity = get_identity(ctx);
	} else if (magic == MARK_MAGIC_HOST) {
		*identity = HOST_ID;
	} else if (magic == MARK_MAGIC_ENCRYPT) {
		*identity = get_identity(ctx);
#if defined(ENABLE_L7_LB)
	} else if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
		*identity = get_epid(ctx); /* endpoint identity, not security identity! */
#endif
	} else {
		*identity = WORLD_ID;
	}

	/* Reset packet mark to avoid hitting routing rules again */
	ctx->mark = 0;

#if defined(ENABLE_L7_LB)
	/* Caller tail calls back to source endpoint egress in this case,
	 * do not log the (world) identity.
	 */
	if (magic != MARK_MAGIC_PROXY_EGRESS_EPID)
#endif
		cilium_dbg(ctx, DBG_INHERIT_IDENTITY, *identity, 0);

	return magic;
}
#endif /* __ctx_is == __ctx_skb */

#endif
