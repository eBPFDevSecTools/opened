// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <ep_config.h>

#define IS_BPF_HOST 1

#define EVENT_SOURCE HOST_EP_ID

/* Host endpoint ID for the template bpf_host object file. Will be replaced
 * at compile-time with the proper host endpoint ID.
 */
#define TEMPLATE_HOST_EP_ID 0xffff

/* These are configuration options which have a default value in their
 * respective header files and must thus be defined beforehand:
 */
/* Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK

/* CB_PROXY_MAGIC overlaps with CB_ENCRYPT_MAGIC */
#define ENCRYPT_OR_PROXY_MAGIC 0

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_ECHO_REPLY section in
 * the bpf_lxc object file.
 */
#define SKIP_ICMPV6_ECHO_HANDLING

#ifndef VLAN_FILTER
# define VLAN_FILTER(ifindex, vlan_id) return false;
#endif

#include "lib/common.h"
#include "lib/edt.h"
#include "lib/arp.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/proxy.h"
#include "lib/trace.h"
#include "lib/identity.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/lb.h"
#include "lib/nodeport.h"
#include "lib/eps.h"
#include "lib/host_firewall.h"
#include "lib/egress_policies.h"
#include "lib/overloadable.h"
#include "lib/encrypt.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 62,
  "endLine": 64,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "allow_vlan",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 __maybe_unused ifindex",
    " __u32 __maybe_unused vlan_id"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool allow_vlan (__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id)\n",
    "{\n",
    "    VLAN_FILTER (ifindex, vlan_id);\n",
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
static __always_inline bool allow_vlan(__u32 __maybe_unused ifindex, __u32 __maybe_unused vlan_id) {
	VLAN_FILTER(ifindex, vlan_id);
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 67,
  "endLine": 82,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "rewrite_dmac_to_host",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 src_identity"
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
    "static __always_inline int rewrite_dmac_to_host (struct  __ctx_buff *ctx, __u32 src_identity)\n",
    "{\n",
    "    union macaddr cilium_net_mac = CILIUM_NET_MAC;\n",
    "    if (eth_store_daddr (ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0)\n",
    "        return send_drop_notify_error (ctx, src_identity, DROP_WRITE_ERROR, CTX_ACT_OK, METRIC_INGRESS);\n",
    "    return CTX_ACT_OK;\n",
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
static __always_inline int rewrite_dmac_to_host(struct __ctx_buff *ctx,
						__u32 src_identity)
{
	/* When attached to cilium_host, we rewrite the DMAC to the mac of
	 * cilium_host (peer) to ensure the packet is being considered to be
	 * addressed to the host (PACKET_HOST).
	 */
	union macaddr cilium_net_mac = CILIUM_NET_MAC;

	/* Rewrite to destination MAC of cilium_net (remote peer) */
	if (eth_store_daddr(ctx, (__u8 *) &cilium_net_mac.addr, 0) < 0)
		return send_drop_notify_error(ctx, src_identity, DROP_WRITE_ERROR,
					      CTX_ACT_OK, METRIC_INGRESS);

	return CTX_ACT_OK;
}

#define SECCTX_FROM_IPCACHE_OK	2
#ifndef SECCTX_FROM_IPCACHE
# define SECCTX_FROM_IPCACHE	0
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 89,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "identity_from_ipcache_ok",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool identity_from_ipcache_ok (void)\n",
    "{\n",
    "    return SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;\n",
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
static __always_inline bool identity_from_ipcache_ok(void)
{
	return SECCTX_FROM_IPCACHE == SECCTX_FROM_IPCACHE_OK;
}
#endif

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 96,
  "endLine": 112,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "derive_src_id",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union v6addr *node_ip",
    " struct ipv6hdr *ip6",
    " __u32 *identity"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 derive_src_id (const union v6addr *node_ip, struct ipv6hdr *ip6, __u32 *identity)\n",
    "{\n",
    "    if (ipv6_match_prefix_64 ((union v6addr *) &ip6->saddr, node_ip)) {\n",
    "        __u32 *tmp = (__u32 *) ip6;\n",
    "        *identity = bpf_ntohl (*tmp & IPV6_FLOWLABEL_MASK);\n",
    "        if (*identity == HOST_ID)\n",
    "            return DROP_INVALID_IDENTITY;\n",
    "    }\n",
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
static __always_inline __u32
derive_src_id(const union v6addr *node_ip, struct ipv6hdr *ip6, __u32 *identity)
{
	if (ipv6_match_prefix_64((union v6addr *) &ip6->saddr, node_ip)) {
		/* Read initial 4 bytes of header and then extract flowlabel */
		__u32 *tmp = (__u32 *) ip6;
		*identity = bpf_ntohl(*tmp & IPV6_FLOWLABEL_MASK);

		/* A remote node will map any HOST_ID source to be presented as
		 * REMOTE_NODE_ID, therefore any attempt to signal HOST_ID as
		 * source from a remote node can be dropped.
		 */
		if (*identity == HOST_ID)
			return DROP_INVALID_IDENTITY;
	}
	return 0;
}

# ifdef ENABLE_HOST_FIREWALL
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 115,
  "endLine": 133,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "ipcache_lookup_srcid6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 ipcache_lookup_srcid6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct remote_endpoint_info *info = NULL;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    __u32 srcid = 0;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    info = lookup_ip6_remote_endpoint ((union v6addr *) & ip6 -> saddr);\n",
    "    if (info != NULL)\n",
    "        srcid = info->sec_label;\n",
    "    cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6, ip6->saddr.s6_addr32[3], srcid);\n",
    "    return srcid;\n",
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
static __always_inline __u32
ipcache_lookup_srcid6(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info *info = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u32 srcid = 0;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	info = lookup_ip6_remote_endpoint((union v6addr *) &ip6->saddr);
	if (info != NULL)
		srcid = info->sec_label;
	cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
		   ip6->saddr.s6_addr32[3], srcid);

	return srcid;
}
# endif /* ENABLE_HOST_FIREWALL */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 136,
  "endLine": 176,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "resolve_srcid_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 srcid_from_proxy",
    " const bool from_host"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 resolve_srcid_ipv6 (struct  __ctx_buff *ctx, __u32 srcid_from_proxy, const bool from_host)\n",
    "{\n",
    "    __u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;\n",
    "    struct remote_endpoint_info *info = NULL;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    union v6addr *src;\n",
    "    int ret;\n",
    "    if (!revalidate_data_maybe_pull (ctx, &data, &data_end, &ip6, !from_host))\n",
    "        return DROP_INVALID;\n",
    "    if (!from_host) {\n",
    "        union v6addr node_ip = {}\n",
    "        ;\n",
    "        BPF_V6 (node_ip, ROUTER_IP);\n",
    "        ret = derive_src_id (& node_ip, ip6, & src_id);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (identity_is_reserved (srcid_from_ipcache)) {\n",
    "        src = (union v6addr *) &ip6->saddr;\n",
    "        info = lookup_ip6_remote_endpoint (src);\n",
    "        if (info != NULL && info->sec_label)\n",
    "            srcid_from_ipcache = info->sec_label;\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6, ((__u32 *) src)[3], srcid_from_ipcache);\n",
    "    }\n",
    "    if (from_host)\n",
    "        src_id = srcid_from_ipcache;\n",
    "    else if (src_id == WORLD_ID && identity_from_ipcache_ok () && !identity_is_reserved (srcid_from_ipcache))\n",
    "        src_id = srcid_from_ipcache;\n",
    "    return src_id;\n",
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
static __always_inline __u32
resolve_srcid_ipv6(struct __ctx_buff *ctx, __u32 srcid_from_proxy,
		   const bool from_host)
{
	__u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;
	struct remote_endpoint_info *info = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *src;
	int ret;

	if (!revalidate_data_maybe_pull(ctx, &data, &data_end, &ip6, !from_host))
		return DROP_INVALID;

	if (!from_host) {
		union v6addr node_ip = {};

		BPF_V6(node_ip, ROUTER_IP);
		ret = derive_src_id(&node_ip, ip6, &src_id);
		if (IS_ERR(ret))
			return ret;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		src = (union v6addr *) &ip6->saddr;
		info = lookup_ip6_remote_endpoint(src);
		if (info != NULL && info->sec_label)
			srcid_from_ipcache = info->sec_label;
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *) src)[3], srcid_from_ipcache);
	}

	if (from_host)
		src_id = srcid_from_ipcache;
	else if (src_id == WORLD_ID &&
		 identity_from_ipcache_ok() &&
		 !identity_is_reserved(srcid_from_ipcache))
		src_id = srcid_from_ipcache;
	return src_id;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool skip_redirect ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t#endif #if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)\t\tif (!from_host)\t\tskip_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t#endif \tif skip_\t\treturn CTX_ACT_OK"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " encap_and__with_nodeidctx",
          " info->tunnel_endpoint",
          "\t\t\t\t\t\t     info->key",
          " secctx",
          " &trace"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " encap_and__netdevctx",
          " &key",
          " secctx",
          " &trace"
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t\t\t\tep_ctx",
          " CILIUM_CALL_SRV6_DECAP"
        ]
      }
    ]
  },
  "startLine": 178,
  "endLine": 351,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 secctx",
    " const bool from_host"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect",
    "tail_call"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_act",
    "xdp",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int handle_ipv6 (struct  __ctx_buff *ctx, __u32 secctx, const bool from_host)\n",
    "{\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = TRACE_PAYLOAD_LEN,}\n",
    "    ;\n",
    "    struct remote_endpoint_info *info = NULL;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    union v6addr *dst;\n",
    "    __u32 __maybe_unused remote_id = WORLD_ID;\n",
    "    int ret, l3_off = ETH_HLEN, hdrlen;\n",
    "    bool skip_redirect = false;\n",
    "    struct endpoint_info *ep;\n",
    "    __u8 nexthdr;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    nexthdr = ip6->nexthdr;\n",
    "    hdrlen = ipv6_hdrlen (ctx, & nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    if (likely (nexthdr == IPPROTO_ICMPV6)) {\n",
    "        ret = icmp6_host_handle (ctx);\n",
    "        if (ret == SKIP_HOST_FIREWALL)\n",
    "            goto skip_host_firewall;\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    if (!from_host) {\n",
    "        if (ctx_get_xfer (ctx) != XFER_PKT_NO_SVC && !bpf_skip_nodeport (ctx)) {\n",
    "            ret = nodeport_lb6 (ctx, secctx);\n",
    "            if (ret < 0 || ret == TC_ACT_REDIRECT)\n",
    "                return ret;\n",
    "        }\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "\n",
    "#if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)\n",
    "    if (!from_host)\n",
    "        skip_redirect = true;\n",
    "\n",
    "#endif /* NO_REDIRECT && !ENABLE_HOST_ROUTING */\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "    if (from_host) {\n",
    "        ret = ipv6_host_policy_egress (ctx, secctx, & trace);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    else if (!ctx_skip_host_fw (ctx)) {\n",
    "        ret = ipv6_host_policy_ingress (ctx, & remote_id, & trace);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "    if (skip_redirect)\n",
    "        return CTX_ACT_OK;\n",
    "skip_host_firewall :\n",
    "\n",
    "#ifdef ENABLE_SRV6\n",
    "    if (!from_host) {\n",
    "        if (is_srv6_packet (ip6) && srv6_lookup_sid (&ip6->daddr)) {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_SRV6_DECAP);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_SRV6 */\n",
    "    if (from_host) {\n",
    "        ret = rewrite_dmac_to_host (ctx, secctx);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "    }\n",
    "    ep = lookup_ip6_endpoint (ip6);\n",
    "    if (ep) {\n",
    "        if (ep->flags & ENDPOINT_F_HOST)\n",
    "            return CTX_ACT_OK;\n",
    "        return ipv6_local_delivery (ctx, l3_off, secctx, ep, METRIC_INGRESS, from_host);\n",
    "    }\n",
    "    if (!from_host)\n",
    "        return CTX_ACT_OK;\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    dst = (union v6addr *) &ip6->daddr;\n",
    "    info = ipcache_lookup6 (& IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);\n",
    "    if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "        ret = encap_and_redirect_with_nodeid (ctx, info -> tunnel_endpoint, info -> key, secctx, & trace);\n",
    "        if (ret == IPSEC_ENDPOINT)\n",
    "            return CTX_ACT_OK;\n",
    "        else\n",
    "            return ret;\n",
    "    }\n",
    "    else {\n",
    "        struct endpoint_key key = {}\n",
    "        ;\n",
    "        dst = (union v6addr *) &ip6->daddr;\n",
    "        key.ip6.p1 = dst->p1;\n",
    "        key.ip6.p2 = dst->p2;\n",
    "        key.ip6.p3 = dst->p3;\n",
    "        key.ip6.p4 = 0;\n",
    "        key.family = ENDPOINT_KEY_IPV6;\n",
    "        ret = encap_and_redirect_netdev (ctx, & key, secctx, & trace);\n",
    "        if (ret == IPSEC_ENDPOINT)\n",
    "            return CTX_ACT_OK;\n",
    "        else if (ret != DROP_NO_TUNNEL_ENDPOINT)\n",
    "            return ret;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    dst = (union v6addr *) &ip6->daddr;\n",
    "    info = ipcache_lookup6 (& IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);\n",
    "    if (info == NULL || info->sec_label == WORLD_ID) {\n",
    "        return DROP_UNROUTABLE;\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    if (info && info->key && info->tunnel_endpoint) {\n",
    "        __u8 key = get_min_encrypt_key (info -> key);\n",
    "        set_encrypt_key_meta (ctx, key);\n",
    "\n",
    "#ifdef IP_POOLS\n",
    "        set_encrypt_dip (ctx, info->tunnel_endpoint);\n",
    "\n",
    "#else\n",
    "        set_identity_meta (ctx, secctx);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    return CTX_ACT_OK;\n",
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
static __always_inline int
handle_ipv6(struct __ctx_buff *ctx, __u32 secctx, const bool from_host)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	struct remote_endpoint_info *info = NULL;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *dst;
	__u32 __maybe_unused remote_id = WORLD_ID;
	int ret, l3_off = ETH_HLEN, hdrlen;
	bool skip_redirect = false;
	struct endpoint_info *ep;
	__u8 nexthdr;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx);
		if (ret == SKIP_HOST_FIREWALL)
			goto skip_host_firewall;
		if (IS_ERR(ret))
			return ret;
	}

#ifdef ENABLE_NODEPORT
	if (!from_host) {
		if (ctx_get_xfer(ctx) != XFER_PKT_NO_SVC &&
		    !bpf_skip_nodeport(ctx)) {
			ret = nodeport_lb6(ctx, secctx);
			/* nodeport_lb6() returns with TC_ACT_REDIRECT for
			 * traffic to L7 LB. Policy enforcement needs to take
			 * place after L7 LB has processed the packet, so we
			 * return to stack immediately here with
			 * TC_ACT_REDIRECT.
			 */
			if (ret < 0 || ret == TC_ACT_REDIRECT)
				return ret;
		}
		/* Verifier workaround: modified ctx access. */
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
	}
#endif /* ENABLE_NODEPORT */

#if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)
	/* See IPv4 case for NO_REDIRECT/ENABLE_HOST_ROUTING comments */
	if (!from_host)
		skip_redirect = true;
#endif /* NO_REDIRECT && !ENABLE_HOST_ROUTING */

#ifdef ENABLE_HOST_FIREWALL
	if (from_host) {
		ret = ipv6_host_policy_egress(ctx, secctx, &trace);
		if (IS_ERR(ret))
			return ret;
	} else if (!ctx_skip_host_fw(ctx)) {
		ret = ipv6_host_policy_ingress(ctx, &remote_id, &trace);
		if (IS_ERR(ret))
			return ret;
	}
#endif /* ENABLE_HOST_FIREWALL */

	if (skip_redirect)
		return CTX_ACT_OK;

skip_host_firewall:
#ifdef ENABLE_SRV6
	if (!from_host) {
		if (is_srv6_packet(ip6) && srv6_lookup_sid(&ip6->daddr)) {
			/* This packet is destined to an SID so we need to decapsulate it
			 * and forward it.
			 */
			ep_tail_call(ctx, CILIUM_CALL_SRV6_DECAP);
			return DROP_MISSED_TAIL_CALL;
		}
	}
#endif /* ENABLE_SRV6 */

	if (from_host) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx, secctx);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
	}

	/* Lookup IPv6 address in list of local endpoints */
	ep = lookup_ip6_endpoint(ip6);
	if (ep) {
		/* Let through packets to the node-ip so they are
		 * processed by the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
			return CTX_ACT_OK;

		return ipv6_local_delivery(ctx, l3_off, secctx, ep,
					   METRIC_INGRESS, from_host);
	}

	/* Below remainder is only relevant when traffic is pushed via cilium_host.
	 * For traffic coming from external, we're done here.
	 */
	if (!from_host)
		return CTX_ACT_OK;

#ifdef TUNNEL_MODE
	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
	if (info != NULL && info->tunnel_endpoint != 0) {
		ret = encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						     info->key, secctx, &trace);

		/* If IPSEC is needed recirc through ingress to use xfrm stack
		 * and then result will routed back through bpf_netdev on egress
		 * but with encrypt marks.
		 */
		if (ret == IPSEC_ENDPOINT)
			return CTX_ACT_OK;
		else
			return ret;
	} else {
		struct endpoint_key key = {};

		/* IPv6 lookup key: daddr/96 */
		dst = (union v6addr *) &ip6->daddr;
		key.ip6.p1 = dst->p1;
		key.ip6.p2 = dst->p2;
		key.ip6.p3 = dst->p3;
		key.ip6.p4 = 0;
		key.family = ENDPOINT_KEY_IPV6;

		ret = encap_and_redirect_netdev(ctx, &key, secctx, &trace);
		if (ret == IPSEC_ENDPOINT)
			return CTX_ACT_OK;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	dst = (union v6addr *) &ip6->daddr;
	info = ipcache_lookup6(&IPCACHE_MAP, dst, V6_CACHE_KEY_LEN);
	if (info == NULL || info->sec_label == WORLD_ID) {
		/* See IPv4 comment. */
		return DROP_UNROUTABLE;
	}

#ifdef ENABLE_IPSEC
	if (info && info->key && info->tunnel_endpoint) {
		__u8 key = get_min_encrypt_key(info->key);

		set_encrypt_key_meta(ctx, key);
#ifdef IP_POOLS
		set_encrypt_dip(ctx, info->tunnel_endpoint);
#else
		set_identity_meta(ctx, secctx);
#endif
	}
#endif
	return CTX_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 353,
  "endLine": 366,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const bool from_host"
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
    "static __always_inline int tail_handle_ipv6 (struct  __ctx_buff *ctx, const bool from_host)\n",
    "{\n",
    "    __u32 proxy_identity = ctx_load_meta (ctx, CB_SRC_IDENTITY);\n",
    "    int ret;\n",
    "    ctx_store_meta (ctx, CB_SRC_IDENTITY, 0);\n",
    "    ret = handle_ipv6 (ctx, proxy_identity, from_host);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, proxy_identity, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    return ret;\n",
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
static __always_inline int
tail_handle_ipv6(struct __ctx_buff *ctx, const bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_IDENTITY);
	int ret;

	ctx_store_meta(ctx, CB_SRC_IDENTITY, 0);

	ret = handle_ipv6(ctx, proxy_identity, from_host);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, proxy_identity, ret,
					      CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_HOST)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 369,
  "endLine": 372,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv6_from_host",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "int",
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
    "int tail_handle_ipv6_from_host (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    return tail_handle_ipv6 (ctx, true);\n",
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
int tail_handle_ipv6_from_host(struct __ctx_buff *ctx __maybe_unused)
{
	return tail_handle_ipv6(ctx, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 375,
  "endLine": 378,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv6_from_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_handle_ipv6_from_netdev (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return tail_handle_ipv6 (ctx, false);\n",
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
int tail_handle_ipv6_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv6(ctx, false);
}

# ifdef ENABLE_HOST_FIREWALL
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 381,
  "endLine": 409,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_to_netdev_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct trace_ctx *trace"
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
    "static __always_inline int handle_to_netdev_ipv6 (struct  __ctx_buff *ctx, struct trace_ctx *trace)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int hdrlen, ret;\n",
    "    __u32 src_id = 0;\n",
    "    __u8 nexthdr;\n",
    "    if (!revalidate_data_pull (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    nexthdr = ip6->nexthdr;\n",
    "    hdrlen = ipv6_hdrlen (ctx, & nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    if (likely (nexthdr == IPPROTO_ICMPV6)) {\n",
    "        ret = icmp6_host_handle (ctx);\n",
    "        if (ret == SKIP_HOST_FIREWALL)\n",
    "            return CTX_ACT_OK;\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    src_id = ipcache_lookup_srcid6 (ctx);\n",
    "    return ipv6_host_policy_egress (ctx, src_id, trace);\n",
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
static __always_inline int
handle_to_netdev_ipv6(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int hdrlen, ret;
	__u32 src_id = 0;
	__u8 nexthdr;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	if (likely(nexthdr == IPPROTO_ICMPV6)) {
		ret = icmp6_host_handle(ctx);
		if (ret == SKIP_HOST_FIREWALL)
			return CTX_ACT_OK;
		if (IS_ERR(ret))
			return ret;
	}

	/* to-netdev is attached to the egress path of the native device. */
	src_id = ipcache_lookup_srcid6(ctx);
	return ipv6_host_policy_egress(ctx, src_id, trace);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 414,
  "endLine": 469,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "resolve_srcid_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 srcid_from_proxy",
    " __u32 *sec_label",
    " const bool from_host"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 resolve_srcid_ipv4 (struct  __ctx_buff *ctx, __u32 srcid_from_proxy, __u32 *sec_label, const bool from_host)\n",
    "{\n",
    "    __u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;\n",
    "    struct remote_endpoint_info *info = NULL;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    if (!revalidate_data_maybe_pull (ctx, &data, &data_end, &ip4, !from_host))\n",
    "        return DROP_INVALID;\n",
    "    if (identity_is_reserved (srcid_from_ipcache)) {\n",
    "        info = lookup_ip4_remote_endpoint (ip4 -> saddr);\n",
    "        if (info != NULL) {\n",
    "            *sec_label = info->sec_label;\n",
    "            if (*sec_label) {\n",
    "\n",
    "#ifndef ENABLE_EXTRA_HOST_DEV\n",
    "                if (*sec_label != HOST_ID)\n",
    "                    srcid_from_ipcache = *sec_label;\n",
    "\n",
    "#else\n",
    "                if ((*sec_label != HOST_ID && !from_host) || from_host)\n",
    "                    srcid_from_ipcache = *sec_label;\n",
    "\n",
    "#endif /* ENABLE_EXTRA_HOST_DEV */\n",
    "            }\n",
    "        }\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4, ip4->saddr, srcid_from_ipcache);\n",
    "    }\n",
    "    if (from_host)\n",
    "        src_id = srcid_from_ipcache;\n",
    "    else if (identity_from_ipcache_ok () && !identity_is_reserved (srcid_from_ipcache))\n",
    "        src_id = srcid_from_ipcache;\n",
    "    return src_id;\n",
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
static __always_inline __u32
resolve_srcid_ipv4(struct __ctx_buff *ctx, __u32 srcid_from_proxy,
		   __u32 *sec_label, const bool from_host)
{
	__u32 src_id = WORLD_ID, srcid_from_ipcache = srcid_from_proxy;
	struct remote_endpoint_info *info = NULL;
	void *data, *data_end;
	struct iphdr *ip4;

	/* This is the first time revalidate_data() is going to be called in
	 * the "to-netdev" path. Make sure that we don't legitimately drop
	 * the packet if the skb arrived with the header not being not in the
	 * linear data.
	 */
	if (!revalidate_data_maybe_pull(ctx, &data, &data_end, &ip4, !from_host))
		return DROP_INVALID;

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(srcid_from_ipcache)) {
		info = lookup_ip4_remote_endpoint(ip4->saddr);
		if (info != NULL) {
			*sec_label = info->sec_label;

			if (*sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "srcid_from_proxy"
				 * (passed into this function) reports the src as
				 * the host. So we can ignore the ipcache if it
				 * reports the source as HOST_ID.
				 */
#ifndef ENABLE_EXTRA_HOST_DEV
				if (*sec_label != HOST_ID)
					srcid_from_ipcache = *sec_label;
#else
				if ((*sec_label != HOST_ID &&
				     !from_host) || from_host)
					srcid_from_ipcache = *sec_label;
#endif /* ENABLE_EXTRA_HOST_DEV */
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, srcid_from_ipcache);
	}

	if (from_host)
		src_id = srcid_from_ipcache;
	/* If we could not derive the secctx from the packet itself but
	 * from the ipcache instead, then use the ipcache identity.
	 */
	else if (identity_from_ipcache_ok() &&
		 !identity_is_reserved(srcid_from_ipcache))
		src_id = srcid_from_ipcache;
	return src_id;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool skip_redirect ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t#endif #if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)\t\tif (!from_host)\t\tskip_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t#endif \tif skip_\t\treturn CTX_ACT_OK"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\treturn __encap_and__with_nodeidctx",
          " vtep->tunnel_endpoint",
          "\t\t\t\t\t\t\t\tsecctx",
          " WORLD_ID",
          " &trace"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " encap_and__with_nodeidctx",
          " info->tunnel_endpoint",
          "\t\t\t\t\t\t     info->key",
          " secctx",
          " &trace"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " encap_and__netdevctx",
          " &key",
          " secctx",
          " &trace"
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_NETDEV"
        ]
      }
    ],
    "map_lookup_elem": [
      {
        "opVar": "\t\tvtep ",
        "inpVar": [
          " &VTEP_MAP",
          " &vkey"
        ]
      }
    ]
  },
  "startLine": 471,
  "endLine": 671,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_ipv4",
  "updateMaps": [],
  "readMaps": [
    "  VTEP_MAP"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 secctx",
    " __u32 ipcache_srcid __maybe_unused",
    " const bool from_host"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect",
    "map_lookup_elem",
    "tail_call"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_act",
    "xdp",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int handle_ipv4 (struct  __ctx_buff *ctx, __u32 secctx, __u32 ipcache_srcid __maybe_unused, const bool from_host)\n",
    "{\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = TRACE_PAYLOAD_LEN,}\n",
    "    ;\n",
    "    struct remote_endpoint_info *info = NULL;\n",
    "    __u32 __maybe_unused remote_id = 0;\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    bool skip_redirect = false;\n",
    "    struct endpoint_info *ep;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    int ret;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "\n",
    "#ifndef ENABLE_IPV4_FRAGMENTS\n",
    "    if (ipv4_is_fragment (ip4))\n",
    "        return DROP_FRAG_NOSUPPORT;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    if (!from_host) {\n",
    "        if (ctx_get_xfer (ctx) != XFER_PKT_NO_SVC && !bpf_skip_nodeport (ctx)) {\n",
    "            ret = nodeport_lb4 (ctx, secctx);\n",
    "            if (ret == NAT_46X64_RECIRC) {\n",
    "                ctx_store_meta (ctx, CB_SRC_IDENTITY, secctx);\n",
    "                ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "                return send_drop_notify_error (ctx, secctx, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "            }\n",
    "            if (ret < 0 || ret == TC_ACT_REDIRECT)\n",
    "                return ret;\n",
    "        }\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "\n",
    "#if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)\n",
    "    if (!from_host)\n",
    "        skip_redirect = true;\n",
    "\n",
    "#endif /* NO_REDIRECT && !ENABLE_HOST_ROUTING */\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "    if (from_host) {\n",
    "        ret = ipv4_host_policy_egress (ctx, secctx, ipcache_srcid, & trace);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    else if (!ctx_skip_host_fw (ctx)) {\n",
    "        ret = ipv4_host_policy_ingress (ctx, & remote_id, & trace);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "    if (skip_redirect)\n",
    "        return CTX_ACT_OK;\n",
    "    tuple.nexthdr = ip4->protocol;\n",
    "    if (from_host) {\n",
    "        ret = rewrite_dmac_to_host (ctx, secctx);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "    }\n",
    "    ep = lookup_ip4_endpoint (ip4);\n",
    "    if (ep) {\n",
    "        if (ep->flags & ENDPOINT_F_HOST)\n",
    "            return CTX_ACT_OK;\n",
    "        return ipv4_local_delivery (ctx, ETH_HLEN, secctx, ip4, ep, METRIC_INGRESS, from_host);\n",
    "    }\n",
    "    if (!from_host)\n",
    "        return CTX_ACT_OK;\n",
    "\n",
    "#ifdef ENABLE_VTEP\n",
    "    {\n",
    "        struct vtep_key vkey = {}\n",
    "        ;\n",
    "        struct vtep_value *vtep;\n",
    "        vkey.vtep_ip = ip4->daddr & VTEP_MASK;\n",
    "        vtep = map_lookup_elem (& VTEP_MAP, & vkey);\n",
    "        if (!vtep)\n",
    "            goto skip_vtep;\n",
    "        if (vtep->vtep_mac && vtep->tunnel_endpoint) {\n",
    "            if (eth_store_daddr (ctx, (__u8 *) &vtep->vtep_mac, 0) < 0)\n",
    "                return DROP_WRITE_ERROR;\n",
    "            return __encap_and_redirect_with_nodeid (ctx, vtep->tunnel_endpoint, secctx, WORLD_ID, &trace);\n",
    "        }\n",
    "    }\n",
    "skip_vtep :\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "    info = ipcache_lookup4 (& IPCACHE_MAP, ip4 -> daddr, V4_CACHE_KEY_LEN);\n",
    "    if (info != NULL && info->tunnel_endpoint != 0) {\n",
    "        ret = encap_and_redirect_with_nodeid (ctx, info -> tunnel_endpoint, info -> key, secctx, & trace);\n",
    "        if (ret == IPSEC_ENDPOINT)\n",
    "            return CTX_ACT_OK;\n",
    "        else\n",
    "            return ret;\n",
    "    }\n",
    "    else {\n",
    "        struct endpoint_key key = {}\n",
    "        ;\n",
    "        key.ip4 = ip4->daddr & IPV4_MASK;\n",
    "        key.family = ENDPOINT_KEY_IPV4;\n",
    "        cilium_dbg (ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);\n",
    "        ret = encap_and_redirect_netdev (ctx, & key, secctx, & trace);\n",
    "        if (ret == IPSEC_ENDPOINT)\n",
    "            return CTX_ACT_OK;\n",
    "        else if (ret != DROP_NO_TUNNEL_ENDPOINT)\n",
    "            return ret;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    info = ipcache_lookup4 (& IPCACHE_MAP, ip4 -> daddr, V4_CACHE_KEY_LEN);\n",
    "    if (info == NULL || info->sec_label == WORLD_ID) {\n",
    "        return DROP_UNROUTABLE;\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    if (info && info->key && info->tunnel_endpoint) {\n",
    "        __u8 key = get_min_encrypt_key (info -> key);\n",
    "        set_encrypt_key_meta (ctx, key);\n",
    "\n",
    "#ifdef IP_POOLS\n",
    "        set_encrypt_dip (ctx, info->tunnel_endpoint);\n",
    "\n",
    "#else\n",
    "        set_identity_meta (ctx, secctx);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    return CTX_ACT_OK;\n",
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
static __always_inline int
handle_ipv4(struct __ctx_buff *ctx, __u32 secctx,
	    __u32 ipcache_srcid __maybe_unused, const bool from_host)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	struct remote_endpoint_info *info = NULL;
	__u32 __maybe_unused remote_id = 0;
	struct ipv4_ct_tuple tuple = {};
	bool skip_redirect = false;
	struct endpoint_info *ep;
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

#ifdef ENABLE_NODEPORT
	if (!from_host) {
		if (ctx_get_xfer(ctx) != XFER_PKT_NO_SVC &&
		    !bpf_skip_nodeport(ctx)) {
			ret = nodeport_lb4(ctx, secctx);
			if (ret == NAT_46X64_RECIRC) {
				ctx_store_meta(ctx, CB_SRC_IDENTITY, secctx);
				ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
				return send_drop_notify_error(ctx, secctx,
							      DROP_MISSED_TAIL_CALL,
							      CTX_ACT_DROP,
							      METRIC_INGRESS);
			}

			/* nodeport_lb4() returns with TC_ACT_REDIRECT for
			 * traffic to L7 LB. Policy enforcement needs to take
			 * place after L7 LB has processed the packet, so we
			 * return to stack immediately here with
			 * TC_ACT_REDIRECT.
			 */
			if (ret < 0 || ret == TC_ACT_REDIRECT)
				return ret;
		}
		/* Verifier workaround: modified ctx access. */
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}
#endif /* ENABLE_NODEPORT */

#if defined(NO_REDIRECT) && !defined(ENABLE_HOST_ROUTING)
	/* Without bpf_redirect_neigh() helper, we cannot redirect a
	 * packet to a local endpoint in the direct routing mode, as
	 * the redirect bypasses nf_conntrack table. This makes a
	 * second reply from the endpoint to be MASQUERADEd or to be
	 * DROP-ed by k8s's "--ctstate INVALID -j DROP" depending via
	 * which interface it was inputed. With bpf_redirect_neigh()
	 * we bypass request and reply path in the host namespace and
	 * do not run into this issue.
	 */
	if (!from_host)
		skip_redirect = true;
#endif /* NO_REDIRECT && !ENABLE_HOST_ROUTING */

#ifdef ENABLE_HOST_FIREWALL
	if (from_host) {
		/* We're on the egress path of cilium_host. */
		ret = ipv4_host_policy_egress(ctx, secctx, ipcache_srcid,
					      &trace);
		if (IS_ERR(ret))
			return ret;
	} else if (!ctx_skip_host_fw(ctx)) {
		/* We're on the ingress path of the native device. */
		ret = ipv4_host_policy_ingress(ctx, &remote_id, &trace);
		if (IS_ERR(ret))
			return ret;
	}
#endif /* ENABLE_HOST_FIREWALL */

	if (skip_redirect)
		return CTX_ACT_OK;

	tuple.nexthdr = ip4->protocol;

	if (from_host) {
		/* If we are attached to cilium_host at egress, this will
		 * rewrite the destination MAC address to the MAC of cilium_net.
		 */
		ret = rewrite_dmac_to_host(ctx, secctx);
		/* DIRECT PACKET READ INVALID */
		if (IS_ERR(ret))
			return ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}

	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = lookup_ip4_endpoint(ip4);
	if (ep) {
		/* Let through packets to the node-ip so they are processed by
		 * the local ip stack.
		 */
		if (ep->flags & ENDPOINT_F_HOST)
			return CTX_ACT_OK;

		return ipv4_local_delivery(ctx, ETH_HLEN, secctx, ip4, ep,
					   METRIC_INGRESS, from_host);
	}

	/* Below remainder is only relevant when traffic is pushed via cilium_host.
	 * For traffic coming from external, we're done here.
	 */
	if (!from_host)
		return CTX_ACT_OK;

	/* Handle VTEP integration in bpf_host to support pod L7 PROXY.
	 * It requires route setup to VTEP CIDR via dev cilium_host scope link.
	 */
#ifdef ENABLE_VTEP
	{
		struct vtep_key vkey = {};
		struct vtep_value *vtep;

		vkey.vtep_ip = ip4->daddr & VTEP_MASK;
		vtep = map_lookup_elem(&VTEP_MAP, &vkey);
		if (!vtep)
			goto skip_vtep;

		if (vtep->vtep_mac && vtep->tunnel_endpoint) {
			if (eth_store_daddr(ctx, (__u8 *)&vtep->vtep_mac, 0) < 0)
				return DROP_WRITE_ERROR;
			return __encap_and_redirect_with_nodeid(ctx, vtep->tunnel_endpoint,
								secctx, WORLD_ID, &trace);
		}
	}
skip_vtep:
#endif

#ifdef TUNNEL_MODE
	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
	if (info != NULL && info->tunnel_endpoint != 0) {
		ret = encap_and_redirect_with_nodeid(ctx, info->tunnel_endpoint,
						     info->key, secctx, &trace);

		if (ret == IPSEC_ENDPOINT)
			return CTX_ACT_OK;
		else
			return ret;
	} else {
		/* IPv4 lookup key: daddr & IPV4_MASK */
		struct endpoint_key key = {};

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		cilium_dbg(ctx, DBG_NETDEV_ENCAP4, key.ip4, secctx);
		ret = encap_and_redirect_netdev(ctx, &key, secctx, &trace);
		if (ret == IPSEC_ENDPOINT)
			return CTX_ACT_OK;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN);
	if (info == NULL || info->sec_label == WORLD_ID) {
		/* We have received a packet for which no ipcache entry exists,
		 * we do not know what to do with this packet, drop it.
		 *
		 * The info == NULL test is soley to satisfy verifier requirements
		 * as in Cilium case we'll always hit the 0.0.0.0/32 catch-all
		 * entry. Therefore we need to test for WORLD_ID. It is clearly
		 * wrong to route a ctx to cilium_host for which we don't know
		 * anything about it as otherwise we'll run into a routing loop.
		 */
		return DROP_UNROUTABLE;
	}

#ifdef ENABLE_IPSEC
	if (info && info->key && info->tunnel_endpoint) {
		__u8 key = get_min_encrypt_key(info->key);

		set_encrypt_key_meta(ctx, key);
#ifdef IP_POOLS
		set_encrypt_dip(ctx, info->tunnel_endpoint);
#else
		set_identity_meta(ctx, secctx);
#endif
	}
#endif
	return CTX_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 673,
  "endLine": 686,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 ipcache_srcid",
    " const bool from_host"
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
    "static __always_inline int tail_handle_ipv4 (struct  __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)\n",
    "{\n",
    "    __u32 proxy_identity = ctx_load_meta (ctx, CB_SRC_IDENTITY);\n",
    "    int ret;\n",
    "    ctx_store_meta (ctx, CB_SRC_IDENTITY, 0);\n",
    "    ret = handle_ipv4 (ctx, proxy_identity, ipcache_srcid, from_host);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, proxy_identity, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    return ret;\n",
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
static __always_inline int
tail_handle_ipv4(struct __ctx_buff *ctx, __u32 ipcache_srcid, const bool from_host)
{
	__u32 proxy_identity = ctx_load_meta(ctx, CB_SRC_IDENTITY);
	int ret;

	ctx_store_meta(ctx, CB_SRC_IDENTITY, 0);

	ret = handle_ipv4(ctx, proxy_identity, ipcache_srcid, from_host);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, proxy_identity,
					      ret, CTX_ACT_DROP, METRIC_INGRESS);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_HOST)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 689,
  "endLine": 699,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv4_from_host",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_handle_ipv4_from_host (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 ipcache_srcid = 0;\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)\n",
    "    ipcache_srcid = ctx_load_meta (ctx, CB_IPCACHE_SRC_LABEL);\n",
    "    ctx_store_meta (ctx, CB_IPCACHE_SRC_LABEL, 0);\n",
    "\n",
    "#endif\n",
    "    return tail_handle_ipv4 (ctx, ipcache_srcid, true);\n",
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
int tail_handle_ipv4_from_host(struct __ctx_buff *ctx)
{
	__u32 ipcache_srcid = 0;

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)
	ipcache_srcid = ctx_load_meta(ctx, CB_IPCACHE_SRC_LABEL);
	ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, 0);
#endif

	return tail_handle_ipv4(ctx, ipcache_srcid, true);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 702,
  "endLine": 705,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_handle_ipv4_from_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_handle_ipv4_from_netdev (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return tail_handle_ipv4 (ctx, 0, false);\n",
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
int tail_handle_ipv4_from_netdev(struct __ctx_buff *ctx)
{
	return tail_handle_ipv4(ctx, 0, false);
}

#ifdef ENABLE_HOST_FIREWALL
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 708,
  "endLine": 727,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_to_netdev_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct trace_ctx *trace"
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
    "static __always_inline int handle_to_netdev_ipv4 (struct  __ctx_buff *ctx, struct trace_ctx *trace)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    __u32 src_id = 0, ipcache_srcid = 0;\n",
    "    if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_HOST)\n",
    "        src_id = HOST_ID;\n",
    "    src_id = resolve_srcid_ipv4 (ctx, src_id, & ipcache_srcid, true);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    return ipv4_host_policy_egress (ctx, src_id, ipcache_srcid, trace);\n",
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
static __always_inline int
handle_to_netdev_ipv4(struct __ctx_buff *ctx, struct trace_ctx *trace)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 src_id = 0, ipcache_srcid = 0;

	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_HOST)
		src_id = HOST_ID;

	src_id = resolve_srcid_ipv4(ctx, src_id, &ipcache_srcid, true);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* We need to pass the srcid from ipcache to host firewall. See
	 * comment in ipv4_host_policy_egress() for details.
	 */
	return ipv4_host_policy_egress(ctx, src_id, ipcache_srcid, trace);
}
#endif /* ENABLE_HOST_FIREWALL */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPSEC
#ifndef TUNNEL_MODE
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
          ]
        }
      ]
    },
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "csum_diff": [
      {
        "opVar": "\t\t\tsum ",
        "inpVar": [
          " &iphdr->daddr",
          " 4",
          " &tunnel_endpoint",
          " 4",
          " 0"
        ]
      },
      {
        "opVar": "\t\tsum ",
        "inpVar": [
          " &iphdr->saddr",
          " 4",
          " &tunnel_source",
          " 4",
          " 0"
        ]
      }
    ],
    "l3_csum_replace": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif ctx",
          " ETH_HLEN + offsetofstruct iphdr",
          " check",
          "\t    0",
          " sum",
          " 0 < 0 "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif ctx",
          " ETH_HLEN + offsetofstruct iphdr",
          " check",
          "\t    0",
          " sum",
          " 0 < 0 "
        ]
      }
    ]
  },
  "startLine": 733,
  "endLine": 788,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev_encrypt_pools",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff",
    "l3_csum_replace"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int do_netdev_encrypt_pools (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    int ret = 0;\n",
    "\n",
    "#ifdef IP_POOLS\n",
    "    __u32 tunnel_endpoint = 0;\n",
    "    void *data, *data_end;\n",
    "    __u32 tunnel_source = IPV4_ENCRYPT_IFACE;\n",
    "    struct iphdr *iphdr;\n",
    "    __be32 sum;\n",
    "    tunnel_endpoint = ctx_load_meta (ctx, CB_ENCRYPT_DST);\n",
    "    ctx->mark = 0;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &iphdr)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    sum = csum_diff (& iphdr -> daddr, 4, & tunnel_endpoint, 4, 0);\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct iphdr, daddr), &tunnel_endpoint, 4, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (l3_csum_replace (ctx, ETH_HLEN + offsetof (struct iphdr, check), 0, sum, 0) < 0) {\n",
    "        ret = DROP_CSUM_L3;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &iphdr)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    sum = csum_diff (& iphdr -> saddr, 4, & tunnel_source, 4, 0);\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct iphdr, saddr), &tunnel_source, 4, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err;\n",
    "    }\n",
    "    if (l3_csum_replace (ctx, ETH_HLEN + offsetof (struct iphdr, check), 0, sum, 0) < 0) {\n",
    "        ret = DROP_CSUM_L3;\n",
    "        goto drop_err;\n",
    "    }\n",
    "drop_err :\n",
    "\n",
    "#endif /* IP_POOLS */\n",
    "    return ret;\n",
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
static __always_inline int
do_netdev_encrypt_pools(struct __ctx_buff *ctx __maybe_unused)
{
	int ret = 0;
#ifdef IP_POOLS
	__u32 tunnel_endpoint = 0;
	void *data, *data_end;
	__u32 tunnel_source = IPV4_ENCRYPT_IFACE;
	struct iphdr *iphdr;
	__be32 sum;

	tunnel_endpoint = ctx_load_meta(ctx, CB_ENCRYPT_DST);
	ctx->mark = 0;

	if (!revalidate_data(ctx, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	/* When IP_POOLS is enabled ip addresses are not
	 * assigned on a per node basis so lacking node
	 * affinity we can not use IP address to assign the
	 * destination IP. Instead rewrite it here from cb[].
	 */
	sum = csum_diff(&iphdr->daddr, 4, &tunnel_endpoint, 4, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
	    &tunnel_endpoint, 4, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		ret = DROP_CSUM_L3;
		goto drop_err;
	}

	if (!revalidate_data(ctx, &data, &data_end, &iphdr)) {
		ret = DROP_INVALID;
		goto drop_err;
	}

	sum = csum_diff(&iphdr->saddr, 4, &tunnel_source, 4, 0);
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
	    &tunnel_source, 4, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err;
	}
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
	    0, sum, 0) < 0) {
		ret = DROP_CSUM_L3;
		goto drop_err;
	}
drop_err:
#endif /* IP_POOLS */
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
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
          ]
        },
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_fib_lookup": [
      {
        "opVar": "\t#if defined(BPF_HAVE_FIB_LOOKUP) && defined(ENCRYPT_IFACE)\tstruct bpf_fib_lookup fib_params ",
        "inpVar": [
          " "
        ]
      }
    ],
    "fib_lookup": [
      {
        "opVar": "\terr ",
        "inpVar": [
          " ctx",
          " &fib_params",
          " sizeoffib_params",
          "\t\t    BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT"
        ]
      }
    ]
  },
  "startLine": 790,
  "endLine": 853,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev_encrypt_fib",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u16 proto __maybe_unused",
    " int * encrypt_iface __maybe_unused",
    " int * ext_err __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_fib_lookup",
    "fib_lookup"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int do_netdev_encrypt_fib (struct  __ctx_buff * ctx __maybe_unused, __u16 proto __maybe_unused, int * encrypt_iface __maybe_unused, int * ext_err __maybe_unused)\n",
    "{\n",
    "    int ret = 0;\n",
    "\n",
    "#if defined(BPF_HAVE_FIB_LOOKUP) && defined(ENCRYPT_IFACE)\n",
    "    struct bpf_fib_lookup fib_params = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    int err;\n",
    "    if (proto == bpf_htons (ETH_P_IP)) {\n",
    "        struct iphdr *ip4;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "            ret = DROP_INVALID;\n",
    "            goto drop_err_fib;\n",
    "        }\n",
    "        fib_params.family = AF_INET;\n",
    "        fib_params.ipv4_src = ip4->saddr;\n",
    "        fib_params.ipv4_dst = ip4->daddr;\n",
    "    }\n",
    "    else {\n",
    "        struct ipv6hdr *ip6;\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "            ret = DROP_INVALID;\n",
    "            goto drop_err_fib;\n",
    "        }\n",
    "        fib_params.family = AF_INET6;\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);\n",
    "        ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);\n",
    "    }\n",
    "    fib_params.ifindex = *encrypt_iface;\n",
    "    err = fib_lookup (ctx, & fib_params, sizeof (fib_params), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);\n",
    "    if (err != 0) {\n",
    "        *ext_err = err;\n",
    "        ret = DROP_NO_FIB;\n",
    "        goto drop_err_fib;\n",
    "    }\n",
    "    if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err_fib;\n",
    "    }\n",
    "    if (eth_store_saddr (ctx, fib_params.smac, 0) < 0) {\n",
    "        ret = DROP_WRITE_ERROR;\n",
    "        goto drop_err_fib;\n",
    "    }\n",
    "    *encrypt_iface = fib_params.ifindex;\n",
    "drop_err_fib :\n",
    "\n",
    "#endif /* BPF_HAVE_FIB_LOOKUP */\n",
    "    return ret;\n",
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
static __always_inline int
do_netdev_encrypt_fib(struct __ctx_buff *ctx __maybe_unused,
		      __u16 proto __maybe_unused,
		      int *encrypt_iface __maybe_unused,
		      int *ext_err __maybe_unused)
{
	int ret = 0;
	/* Only do FIB lookup if both the BPF helper is supported and we know
	 * the egress ineterface. If we don't have an egress interface,
	 * typically in an environment with many egress devs than we have
	 * to let the stack decide how to egress the packet. EKS is the
	 * example of an environment with multiple egress interfaces.
	 */
#if defined(BPF_HAVE_FIB_LOOKUP) && defined(ENCRYPT_IFACE)
	struct bpf_fib_lookup fib_params = {};
	void *data, *data_end;
	int err;

	if (proto ==  bpf_htons(ETH_P_IP)) {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
			ret = DROP_INVALID;
			goto drop_err_fib;
		}

		fib_params.family = AF_INET;
		fib_params.ipv4_src = ip4->saddr;
		fib_params.ipv4_dst = ip4->daddr;
	} else {
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
			ret = DROP_INVALID;
			goto drop_err_fib;
		}

		fib_params.family = AF_INET6;
		ipv6_addr_copy((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);
		ipv6_addr_copy((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);
	}

	fib_params.ifindex = *encrypt_iface;

	err = fib_lookup(ctx, &fib_params, sizeof(fib_params),
		    BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (err != 0) {
		*ext_err = err;
		ret = DROP_NO_FIB;
		goto drop_err_fib;
	}
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err_fib;
	}
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0) {
		ret = DROP_WRITE_ERROR;
		goto drop_err_fib;
	}
	*encrypt_iface = fib_params.ifindex;
drop_err_fib:
#endif /* BPF_HAVE_FIB_LOOKUP */
	return ret;
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
          "#ifdef BPF_HAVE_FIB_LOOKUP\t\tif encrypt_iface\t\treturn ctx_ctx",
          " encrypt_iface",
          " 0"
        ]
      }
    ]
  },
  "startLine": 855,
  "endLine": 885,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev_encrypt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 proto",
    " __u32 src_id"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int do_netdev_encrypt (struct  __ctx_buff *ctx, __u16 proto, __u32 src_id)\n",
    "{\n",
    "    int encrypt_iface = 0;\n",
    "    int ext_err = 0;\n",
    "    int ret = 0;\n",
    "\n",
    "#if defined(ENCRYPT_IFACE) && defined(BPF_HAVE_FIB_LOOKUP)\n",
    "    encrypt_iface = ENCRYPT_IFACE;\n",
    "\n",
    "#endif\n",
    "    ret = do_netdev_encrypt_pools (ctx);\n",
    "    if (ret)\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    ret = do_netdev_encrypt_fib (ctx, proto, & encrypt_iface, & ext_err);\n",
    "    if (ret)\n",
    "        return send_drop_notify_error_ext (ctx, src_id, ret, ext_err, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    bpf_clear_meta (ctx);\n",
    "\n",
    "#ifdef BPF_HAVE_FIB_LOOKUP\n",
    "    if (encrypt_iface)\n",
    "        return ctx_redirect (ctx, encrypt_iface, 0);\n",
    "\n",
    "#endif\n",
    "    return CTX_ACT_OK;\n",
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
static __always_inline int do_netdev_encrypt(struct __ctx_buff *ctx, __u16 proto,
					     __u32 src_id)
{
	int encrypt_iface = 0;
	int ext_err = 0;
	int ret = 0;
#if defined(ENCRYPT_IFACE) && defined(BPF_HAVE_FIB_LOOKUP)
	encrypt_iface = ENCRYPT_IFACE;
#endif
	ret = do_netdev_encrypt_pools(ctx);
	if (ret)
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);

	ret = do_netdev_encrypt_fib(ctx, proto, &encrypt_iface, &ext_err);
	if (ret)
		return send_drop_notify_error_ext(ctx, src_id, ret, ext_err,
						  CTX_ACT_DROP, METRIC_INGRESS);

	bpf_clear_meta(ctx);
#ifdef BPF_HAVE_FIB_LOOKUP
	/* Redirect only works if we have a fib lookup to set the MAC
	 * addresses. Otherwise let the stack do the routing and fib
	 * Note, without FIB lookup implemented the packet may have
	 * incorrect dmac leaving bpf_host so will need to mark as
	 * PACKET_HOST or otherwise fixup MAC addresses.
	 */
	if (encrypt_iface)
		return ctx_redirect(ctx, encrypt_iface, 0);
#endif
	return CTX_ACT_OK;
}

#else /* TUNNEL_MODE */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn __encap_and__with_nodeidctx",
          " tunnel_endpoint",
          " src_id",
          "\t\t\t\t\t\tNOT_VTEP_DST",
          " &trace"
        ]
      }
    ]
  },
  "startLine": 888,
  "endLine": 902,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev_encrypt_encap",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 src_id"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int do_netdev_encrypt_encap (struct  __ctx_buff *ctx, __u32 src_id)\n",
    "{\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_ENCRYPTED,\n",
    "        .monitor = TRACE_PAYLOAD_LEN,}\n",
    "    ;\n",
    "    __u32 tunnel_endpoint = 0;\n",
    "    tunnel_endpoint = ctx_load_meta (ctx, CB_ENCRYPT_DST);\n",
    "    ctx->mark = 0;\n",
    "    bpf_clear_meta (ctx);\n",
    "    return __encap_and_redirect_with_nodeid (ctx, tunnel_endpoint, src_id, NOT_VTEP_DST, &trace);\n",
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
static __always_inline int do_netdev_encrypt_encap(struct __ctx_buff *ctx, __u32 src_id)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_ENCRYPTED,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 tunnel_endpoint = 0;

	tunnel_endpoint = ctx_load_meta(ctx, CB_ENCRYPT_DST);
	ctx->mark = 0;

	bpf_clear_meta(ctx);
	return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint, src_id,
						NOT_VTEP_DST, &trace);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 904,
  "endLine": 908,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev_encrypt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 proto __maybe_unused",
    " __u32 src_id"
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
    "static __always_inline int do_netdev_encrypt (struct  __ctx_buff *ctx, __u16 proto __maybe_unused, __u32 src_id)\n",
    "{\n",
    "    return do_netdev_encrypt_encap (ctx, src_id);\n",
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
static __always_inline int do_netdev_encrypt(struct __ctx_buff *ctx, __u16 proto __maybe_unused,
					     __u32 src_id)
{
	return do_netdev_encrypt_encap(ctx, src_id);
}
#endif /* TUNNEL_MODE */
#endif /* ENABLE_IPSEC */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t_dynamicctx",
          " &POLICY_EGRESSCALL_MAP",
          " lxc_id"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif from_host\t\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_HOST"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\telse\t\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_NETDEV"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "# endif\t\t\tep_ctx",
          " CILIUM_CALL_IPV4_FROM_HOST"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_IPV4_FROM_NETDEV"
        ]
      }
    ]
  },
  "startLine": 912,
  "endLine": 1022,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "do_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 proto",
    " const bool from_host"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "static __always_inline int do_netdev (struct  __ctx_buff *ctx, __u16 proto, const bool from_host)\n",
    "{\n",
    "    __u32 __maybe_unused identity = 0;\n",
    "    __u32 __maybe_unused ipcache_srcid = 0;\n",
    "    int ret;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    if (from_host) {\n",
    "        __u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;\n",
    "        if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {\n",
    "            __u32 lxc_id = get_epid (ctx);\n",
    "            ctx->mark = 0;\n",
    "            tail_call_dynamic (ctx, &POLICY_EGRESSCALL_MAP, lxc_id);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    if (!from_host && !do_decrypt (ctx, proto))\n",
    "        return CTX_ACT_OK;\n",
    "\n",
    "#endif\n",
    "    if (from_host) {\n",
    "        __u32 magic;\n",
    "        enum trace_point trace = TRACE_FROM_HOST;\n",
    "        magic = inherit_identity_from_host (ctx, & identity);\n",
    "        if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)\n",
    "            trace = TRACE_FROM_PROXY;\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "        if (magic == MARK_MAGIC_ENCRYPT) {\n",
    "            send_trace_notify (ctx, TRACE_FROM_STACK, identity, 0, 0, ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED, TRACE_PAYLOAD_LEN);\n",
    "            return do_netdev_encrypt (ctx, proto, identity);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        send_trace_notify (ctx, trace, identity, 0, 0, ctx->ingress_ifindex, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);\n",
    "    }\n",
    "    else {\n",
    "        bpf_skip_nodeport_clear (ctx);\n",
    "        send_trace_notify (ctx, TRACE_FROM_NETWORK, 0, 0, 0, ctx->ingress_ifindex, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);\n",
    "    }\n",
    "    bpf_clear_meta (ctx);\n",
    "    switch (proto) {\n",
    "\n",
    "# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        identity = resolve_srcid_ipv6 (ctx, identity, from_host);\n",
    "        ctx_store_meta (ctx, CB_SRC_IDENTITY, identity);\n",
    "        if (from_host)\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_HOST);\n",
    "        else\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "        return send_drop_notify_error (ctx, identity, DROP_MISSED_TAIL_CALL, CTX_ACT_OK, METRIC_INGRESS);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        identity = resolve_srcid_ipv4 (ctx, identity, &ipcache_srcid, from_host);\n",
    "        ctx_store_meta (ctx, CB_SRC_IDENTITY, identity);\n",
    "        if (from_host) {\n",
    "\n",
    "# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)\n",
    "            ctx_store_meta (ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);\n",
    "\n",
    "# endif\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_HOST);\n",
    "        }\n",
    "        else {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_NETDEV);\n",
    "        }\n",
    "        return send_drop_notify_error (ctx, identity, DROP_MISSED_TAIL_CALL, CTX_ACT_OK, METRIC_INGRESS);\n",
    "\n",
    "#endif\n",
    "    default :\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "        ret = send_drop_notify_error (ctx, identity, DROP_UNKNOWN_L3, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "\n",
    "#else\n",
    "        ret = CTX_ACT_OK;\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "    }\n",
    "    return ret;\n",
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
static __always_inline int
do_netdev(struct __ctx_buff *ctx, __u16 proto, const bool from_host)
{
	__u32 __maybe_unused identity = 0;
	__u32 __maybe_unused ipcache_srcid = 0;
	int ret;

#if defined(ENABLE_L7_LB)
	if (from_host) {
		__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
			__u32 lxc_id = get_epid(ctx);

			ctx->mark = 0;
			tail_call_dynamic(ctx, &POLICY_EGRESSCALL_MAP, lxc_id);
			return DROP_MISSED_TAIL_CALL;
		}
	}
#endif

#ifdef ENABLE_IPSEC
	if (!from_host && !do_decrypt(ctx, proto))
		return CTX_ACT_OK;
#endif

	if (from_host) {
		__u32 magic;
		enum trace_point trace = TRACE_FROM_HOST;

		magic = inherit_identity_from_host(ctx, &identity);
		if (magic == MARK_MAGIC_PROXY_INGRESS ||  magic == MARK_MAGIC_PROXY_EGRESS)
			trace = TRACE_FROM_PROXY;

#ifdef ENABLE_IPSEC
		if (magic == MARK_MAGIC_ENCRYPT) {
			send_trace_notify(ctx, TRACE_FROM_STACK, identity, 0, 0,
					  ctx->ingress_ifindex, TRACE_REASON_ENCRYPTED,
					  TRACE_PAYLOAD_LEN);
			return do_netdev_encrypt(ctx, proto, identity);
		}
#endif

		send_trace_notify(ctx, trace, identity, 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	} else {
		bpf_skip_nodeport_clear(ctx);
		send_trace_notify(ctx, TRACE_FROM_NETWORK, 0, 0, 0,
				  ctx->ingress_ifindex,
				  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	}

	bpf_clear_meta(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		identity = resolve_srcid_ipv6(ctx, identity, from_host);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, identity);
		if (from_host)
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_HOST);
		else
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
		/* See comment below for IPv4. */
		return send_drop_notify_error(ctx, identity, DROP_MISSED_TAIL_CALL,
					      CTX_ACT_OK, METRIC_INGRESS);
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		identity = resolve_srcid_ipv4(ctx, identity, &ipcache_srcid,
					      from_host);
		ctx_store_meta(ctx, CB_SRC_IDENTITY, identity);
		if (from_host) {
# if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_MASQUERADE)
			/* If we don't rely on BPF-based masquerading, we need
			 * to pass the srcid from ipcache to host firewall. See
			 * comment in ipv4_host_policy_egress() for details.
			 */
			ctx_store_meta(ctx, CB_IPCACHE_SRC_LABEL, ipcache_srcid);
# endif
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_HOST);
		} else {
			ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
		}
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed.
		 */
		return send_drop_notify_error(ctx, identity, DROP_MISSED_TAIL_CALL,
					      CTX_ACT_OK, METRIC_INGRESS);
#endif
	default:
#ifdef ENABLE_HOST_FIREWALL
		ret = send_drop_notify_error(ctx, identity, DROP_UNKNOWN_L3,
					     CTX_ACT_DROP, METRIC_INGRESS);
#else
		/* Pass unknown traffic to the stack */
		ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return ret;
}

/**
 * handle_netdev
 * @ctx		The packet context for this program
 * @from_host	True if the packet is from the local host
 *
 * Handle netdev traffic coming towards the Cilium-managed network.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1031,
  "endLine": 1051,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const bool from_host"
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
    "static __always_inline int handle_netdev (struct  __ctx_buff *ctx, const bool from_host)\n",
    "{\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "        int ret = DROP_UNSUPPORTED_L2;\n",
    "        return send_drop_notify (ctx, SECLABEL, WORLD_ID, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#else\n",
    "        send_trace_notify (ctx, TRACE_TO_STACK, HOST_ID, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);\n",
    "        return CTX_ACT_OK;\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "    }\n",
    "    return do_netdev (ctx, proto, from_host);\n",
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
static __always_inline int
handle_netdev(struct __ctx_buff *ctx, const bool from_host)
{
	__u16 proto;

	if (!validate_ethertype(ctx, &proto)) {
#ifdef ENABLE_HOST_FIREWALL
		int ret = DROP_UNSUPPORTED_L2;

		return send_drop_notify(ctx, SECLABEL, WORLD_ID, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);
#else
		send_trace_notify(ctx, TRACE_TO_STACK, HOST_ID, 0, 0, 0,
				  TRACE_REASON_UNKNOWN, 0);
		/* Pass unknown traffic to the stack */
		return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
	}

	return do_netdev(ctx, proto, from_host);
}

#ifdef ENABLE_SRV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_SRV6_REPLY"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tep_ctx",
          " CILIUM_CALL_SRV6_ENCAP"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_SRV6_REPLY"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tep_ctx",
          " CILIUM_CALL_SRV6_ENCAP"
        ]
      }
    ]
  },
  "startLine": 1054,
  "endLine": 1142,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_srv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "static __always_inline handle_srv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 *vrf_id, dst_id, tunnel_ep = 0;\n",
    "    struct srv6_ipv6_2tuple *outer_ips;\n",
    "    struct iphdr * ip4 __maybe_unused;\n",
    "    struct remote_endpoint_info *ep;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    union v6addr *sid;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return DROP_UNSUPPORTED_L2;\n",
    "    switch (proto) {\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "        outer_ips = srv6_lookup_state_entry6 (ip6);\n",
    "        if (outer_ips) {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_SRV6_REPLY);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "        ep = lookup_ip6_remote_endpoint ((union v6addr *) & ip6 -> daddr);\n",
    "        if (ep) {\n",
    "            tunnel_ep = ep->tunnel_endpoint;\n",
    "            dst_id = ep->sec_label;\n",
    "        }\n",
    "        else {\n",
    "            dst_id = WORLD_ID;\n",
    "        }\n",
    "        if (identity_is_cluster (dst_id))\n",
    "            return CTX_ACT_OK;\n",
    "        vrf_id = srv6_lookup_vrf6 (& ip6 -> saddr, & ip6 -> daddr);\n",
    "        if (!vrf_id)\n",
    "            return CTX_ACT_OK;\n",
    "        sid = srv6_lookup_policy6 (* vrf_id, & ip6 -> daddr);\n",
    "        if (!sid)\n",
    "            return CTX_ACT_OK;\n",
    "        srv6_store_meta_sid (ctx, sid);\n",
    "        ctx_store_meta (ctx, CB_SRV6_VRF_ID, *vrf_id);\n",
    "        ep_tail_call (ctx, CILIUM_CALL_SRV6_ENCAP);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "\n",
    "# ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "        outer_ips = srv6_lookup_state_entry4 (ip4);\n",
    "        if (outer_ips) {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_SRV6_REPLY);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "        ep = lookup_ip4_remote_endpoint (ip4 -> daddr);\n",
    "        if (ep) {\n",
    "            tunnel_ep = ep->tunnel_endpoint;\n",
    "            dst_id = ep->sec_label;\n",
    "        }\n",
    "        else {\n",
    "            dst_id = WORLD_ID;\n",
    "        }\n",
    "        if (identity_is_cluster (dst_id))\n",
    "            return CTX_ACT_OK;\n",
    "        vrf_id = srv6_lookup_vrf4 (ip4 -> saddr, ip4 -> daddr);\n",
    "        if (!vrf_id)\n",
    "            return CTX_ACT_OK;\n",
    "        sid = srv6_lookup_policy4 (* vrf_id, ip4 -> daddr);\n",
    "        if (!sid)\n",
    "            return CTX_ACT_OK;\n",
    "        srv6_store_meta_sid (ctx, sid);\n",
    "        ctx_store_meta (ctx, CB_SRV6_VRF_ID, *vrf_id);\n",
    "        ep_tail_call (ctx, CILIUM_CALL_SRV6_ENCAP);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
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
static __always_inline
handle_srv6(struct __ctx_buff *ctx)
{
	__u32 *vrf_id, dst_id, tunnel_ep = 0;
	struct srv6_ipv6_2tuple *outer_ips;
	struct iphdr *ip4 __maybe_unused;
	struct remote_endpoint_info *ep;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *sid;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry6(ip6);
		if (outer_ips) {
			ep_tail_call(ctx, CILIUM_CALL_SRV6_REPLY);
			return DROP_MISSED_TAIL_CALL;
		}

		ep = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr);
		if (ep) {
			tunnel_ep = ep->tunnel_endpoint;
			dst_id = ep->sec_label;
		} else {
			dst_id = WORLD_ID;
		}

		if (identity_is_cluster(dst_id))
			return CTX_ACT_OK;

		vrf_id = srv6_lookup_vrf6(&ip6->saddr, &ip6->daddr);
		if (!vrf_id)
			return CTX_ACT_OK;

		sid = srv6_lookup_policy6(*vrf_id, &ip6->daddr);
		if (!sid)
			return CTX_ACT_OK;

		srv6_store_meta_sid(ctx, sid);
		ctx_store_meta(ctx, CB_SRV6_VRF_ID, *vrf_id);
		ep_tail_call(ctx, CILIUM_CALL_SRV6_ENCAP);
		return DROP_MISSED_TAIL_CALL;
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry4(ip4);
		if (outer_ips) {
			ep_tail_call(ctx, CILIUM_CALL_SRV6_REPLY);
			return DROP_MISSED_TAIL_CALL;
		}

		ep = lookup_ip4_remote_endpoint(ip4->daddr);
		if (ep) {
			tunnel_ep = ep->tunnel_endpoint;
			dst_id = ep->sec_label;
		} else {
			dst_id = WORLD_ID;
		}

		if (identity_is_cluster(dst_id))
			return CTX_ACT_OK;

		vrf_id = srv6_lookup_vrf4(ip4->saddr, ip4->daddr);
		if (!vrf_id)
			return CTX_ACT_OK;

		sid = srv6_lookup_policy4(*vrf_id, ip4->daddr);
		if (!sid)
			return CTX_ACT_OK;

		srv6_store_meta_sid(ctx, sid);
		ctx_store_meta(ctx, CB_SRV6_VRF_ID, *vrf_id);
		ep_tail_call(ctx, CILIUM_CALL_SRV6_ENCAP);
		return DROP_MISSED_TAIL_CALL;
		break;
# endif
	}

	return CTX_ACT_OK;
}
#endif /* ENABLE_SRV6 */

/*
 * from-netdev is attached as a tc ingress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled
 */
__section("from-netdev")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1152,
  "endLine": 1170,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "from_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int from_netdev (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 __maybe_unused vlan_id;\n",
    "    if (ctx->vlan_present) {\n",
    "        vlan_id = ctx->vlan_tci & 0xfff;\n",
    "        if (vlan_id) {\n",
    "            if (allow_vlan (ctx->ifindex, vlan_id))\n",
    "                return CTX_ACT_OK;\n",
    "            else\n",
    "                return send_drop_notify_error (ctx, 0, DROP_VLAN_FILTERED, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "        }\n",
    "    }\n",
    "    return handle_netdev (ctx, false);\n",
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
int from_netdev(struct __ctx_buff *ctx)
{
	__u32 __maybe_unused vlan_id;

	/* Filter allowed vlan id's and pass them back to kernel.
	 */
	if (ctx->vlan_present) {
		vlan_id = ctx->vlan_tci & 0xfff;
		if (vlan_id) {
			if (allow_vlan(ctx->ifindex, vlan_id))
				return CTX_ACT_OK;
			else
				return send_drop_notify_error(ctx, 0, DROP_VLAN_FILTERED,
							      CTX_ACT_DROP, METRIC_INGRESS);
		}
	}

	return handle_netdev(ctx, false);
}

/*
 * from-host is attached as a tc egress filter to the node's 'cilium_host'
 * interface if present.
 */
__section("from-host")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1177,
  "endLine": 1184,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "from_host",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int from_host (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    edt_set_aggregate (ctx, 0);\n",
    "    return handle_netdev (ctx, true);\n",
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
int from_host(struct __ctx_buff *ctx)
{
	/* Traffic from the host ns going through cilium_host device must
	 * not be subject to EDT rate-limiting.
	 */
	edt_set_aggregate(ctx, 0);
	return handle_netdev(ctx, true);
}

/*
 * to-netdev is attached as a tc egress filter to one or more physical devices
 * managed by Cilium (e.g., eth0). This program is only attached when:
 * - the host firewall is enabled, or
 * - BPF NodePort is enabled
 */
__section("to-netdev")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t_dynamicctx",
          " &POLICY_EGRESSCALL_MAP",
          " lxc_id"
        ]
      }
    ]
  },
  "startLine": 1193,
  "endLine": 1319,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "to_netdev",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "int",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "int to_netdev (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u16 __maybe_unused proto = 0;\n",
    "    __u32 __maybe_unused vlan_id;\n",
    "    int ret = CTX_ACT_OK;\n",
    "    bool traced = false;\n",
    "    if (ctx->vlan_present) {\n",
    "        vlan_id = ctx->vlan_tci & 0xfff;\n",
    "        if (vlan_id) {\n",
    "            if (allow_vlan (ctx->ifindex, vlan_id))\n",
    "                return CTX_ACT_OK;\n",
    "            else\n",
    "                return send_drop_notify_error (ctx, 0, DROP_VLAN_FILTERED, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    {\n",
    "        __u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;\n",
    "        if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {\n",
    "            __u32 lxc_id = get_epid (ctx);\n",
    "            ctx->mark = 0;\n",
    "            tail_call_dynamic (ctx, &POLICY_EGRESSCALL_MAP, lxc_id);\n",
    "            return DROP_MISSED_TAIL_CALL;\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "    if (!proto && !validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    policy_clear_mark (ctx);\n",
    "    switch (proto) {\n",
    "\n",
    "# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ret = handle_to_netdev_ipv6 (ctx, &trace);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        {\n",
    "            ret = handle_to_netdev_ipv4 (ctx, & trace);\n",
    "            break;\n",
    "        }\n",
    "\n",
    "# endif\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "\n",
    "#if defined(ENABLE_BANDWIDTH_MANAGER)\n",
    "    ret = edt_sched_departure (ctx);\n",
    "    if (ret == CTX_ACT_DROP) {\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_EGRESS, -DROP_EDT_HORIZON);\n",
    "        return ret;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_SRV6\n",
    "    ret = handle_srv6 (ctx);\n",
    "    if (ret != CTX_ACT_OK)\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#endif /* ENABLE_SRV6 */\n",
    "\n",
    "#if defined(ENABLE_NODEPORT) && \\\n",
    "\t(!defined(ENABLE_DSR) || \\\n",
    "\t (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) || \\\n",
    "\t defined(ENABLE_MASQUERADE) || \\\n",
    "\t defined(ENABLE_EGRESS_GATEWAY))\n",
    "    if ((ctx->mark & MARK_MAGIC_SNAT_DONE) != MARK_MAGIC_SNAT_DONE) {\n",
    "        ret = handle_nat_fwd (ctx);\n",
    "        if (IS_ERR (ret))\n",
    "            return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "        traced = true;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_HEALTH_CHECK\n",
    "    ret = lb_handle_health (ctx);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#endif\n",
    "    if (!traced)\n",
    "        send_trace_notify (ctx, TRACE_TO_NETWORK, 0, 0, 0, 0, trace.reason, trace.monitor);\n",
    "    return ret;\n",
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
int to_netdev(struct __ctx_buff *ctx __maybe_unused)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u16 __maybe_unused proto = 0;
	__u32 __maybe_unused vlan_id;
	int ret = CTX_ACT_OK;
	bool traced = false;

	/* Filter allowed vlan id's and pass them back to kernel.
	 */
	if (ctx->vlan_present) {
		vlan_id = ctx->vlan_tci & 0xfff;
		if (vlan_id) {
			if (allow_vlan(ctx->ifindex, vlan_id))
				return CTX_ACT_OK;
			else
				return send_drop_notify_error(ctx, 0, DROP_VLAN_FILTERED,
							      CTX_ACT_DROP, METRIC_EGRESS);
		}
	}

#if defined(ENABLE_L7_LB)
	{
		__u32 magic = ctx->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
			__u32 lxc_id = get_epid(ctx);

			ctx->mark = 0;
			tail_call_dynamic(ctx, &POLICY_EGRESSCALL_MAP, lxc_id);
			return DROP_MISSED_TAIL_CALL;
		}
	}
#endif

#ifdef ENABLE_HOST_FIREWALL
	if (!proto && !validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	policy_clear_mark(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = handle_to_netdev_ipv6(ctx, &trace);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		ret = handle_to_netdev_ipv4(ctx, &trace);
		break;
	}
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif /* ENABLE_HOST_FIREWALL */

#if defined(ENABLE_BANDWIDTH_MANAGER)
	ret = edt_sched_departure(ctx);
	/* No send_drop_notify_error() here given we're rate-limiting. */
	if (ret == CTX_ACT_DROP) {
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       -DROP_EDT_HORIZON);
		return ret;
	}
#endif

#ifdef ENABLE_SRV6
	ret = handle_srv6(ctx);
	if (ret != CTX_ACT_OK)
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif /* ENABLE_SRV6 */

#if defined(ENABLE_NODEPORT) && \
	(!defined(ENABLE_DSR) || \
	 (defined(ENABLE_DSR) && defined(ENABLE_DSR_HYBRID)) || \
	 defined(ENABLE_MASQUERADE) || \
	 defined(ENABLE_EGRESS_GATEWAY))
	if ((ctx->mark & MARK_MAGIC_SNAT_DONE) != MARK_MAGIC_SNAT_DONE) {
		/*
		 * handle_nat_fwd tail calls in the majority of cases,
		 * so control might never return to this program.
		 */
		ret = handle_nat_fwd(ctx);
		if (IS_ERR(ret))
			return send_drop_notify_error(ctx, 0, ret,
						      CTX_ACT_DROP,
						      METRIC_EGRESS);

		/*
		 * Depending on the condition, handle_nat_fwd may return
		 * without tail calling. Since we have packet tracing inside
		 * the handle_nat_fwd, we need to avoid tracing the packet
		 * twice.
		 */
		traced = true;
	}
#endif
#ifdef ENABLE_HEALTH_CHECK
	ret = lb_handle_health(ctx);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
#endif
	if (!traced)
		send_trace_notify(ctx, TRACE_TO_NETWORK, 0, 0, 0,
				  0, trace.reason, trace.monitor);

	return ret;
}

/*
 * to-host is attached as a tc ingress filter to both the 'cilium_host' and
 * 'cilium_net' devices if present.
 */
__section("to-host")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy_firstctx",
          " port"
        ]
      }
    ]
  },
  "startLine": 1326,
  "endLine": 1406,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "to_host",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int to_host (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 magic = ctx_load_meta (ctx, ENCRYPT_OR_PROXY_MAGIC);\n",
    "    __u16 __maybe_unused proto = 0;\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    int ret = CTX_ACT_OK;\n",
    "    bool traced = false;\n",
    "    __u32 src_id = 0;\n",
    "    if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {\n",
    "        ctx->mark = magic;\n",
    "        src_id = ctx_load_meta (ctx, CB_ENCRYPT_IDENTITY);\n",
    "        set_identity_mark (ctx, src_id);\n",
    "    }\n",
    "    else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {\n",
    "        __be16 port = magic >> 16;\n",
    "        ctx_store_meta (ctx, CB_PROXY_MAGIC, 0);\n",
    "        ret = ctx_redirect_to_proxy_first (ctx, port);\n",
    "        if (IS_ERR (ret))\n",
    "            goto out;\n",
    "        traced = true;\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    ctx_change_type (ctx, PACKET_HOST);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    policy_clear_mark (ctx);\n",
    "    switch (proto) {\n",
    "\n",
    "# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ret = ipv6_host_policy_ingress (ctx, &src_id, &trace);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ret = ipv4_host_policy_ingress (ctx, &src_id, &trace);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "\n",
    "#else\n",
    "    ret = CTX_ACT_OK;\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    if (!traced)\n",
    "        send_trace_notify (ctx, TRACE_TO_STACK, src_id, 0, 0, CILIUM_IFINDEX, trace.reason, trace.monitor);\n",
    "    return ret;\n",
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
int to_host(struct __ctx_buff *ctx)
{
	__u32 magic = ctx_load_meta(ctx, ENCRYPT_OR_PROXY_MAGIC);
	__u16 __maybe_unused proto = 0;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	bool traced = false;
	__u32 src_id = 0;

	if ((magic & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_ENCRYPT) {
		ctx->mark = magic; /* CB_ENCRYPT_MAGIC */
		src_id = ctx_load_meta(ctx, CB_ENCRYPT_IDENTITY);
		set_identity_mark(ctx, src_id);
	} else if ((magic & 0xFFFF) == MARK_MAGIC_TO_PROXY) {
		/* Upper 16 bits may carry proxy port number */
		__be16 port = magic >> 16;

		ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
		ret = ctx_redirect_to_proxy_first(ctx, port);
		if (IS_ERR(ret))
			goto out;
		/* We already traced this in the previous prog with more
		 * background context, skip trace here.
		 */
		traced = true;
	}

#ifdef ENABLE_IPSEC
	/* Encryption stack needs this when IPSec headers are
	 * rewritten without FIB helper because we do not yet
	 * know correct MAC address which will cause the stack
	 * to mark as PACKET_OTHERHOST and drop.
	 */
	ctx_change_type(ctx, PACKET_HOST);
#endif
#ifdef ENABLE_HOST_FIREWALL
	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	policy_clear_mark(ctx);

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_host_policy_ingress(ctx, &src_id, &trace);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = ipv4_host_policy_ingress(ctx, &src_id, &trace);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}
#else
	ret = CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */

out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);

	if (!traced)
		send_trace_notify(ctx, TRACE_TO_STACK, src_id, 0, 0,
				  CILIUM_IFINDEX, trace.reason, trace.monitor);

	return ret;
}

#if defined(ENABLE_HOST_FIREWALL)
#ifdef ENABLE_IPV6
declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1412,
  "endLine": 1426,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_ipv6_host_policy_ingress",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_ipv6_host_policy_ingress (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u32 src_id = 0;\n",
    "    int ret;\n",
    "    ret = ipv6_host_policy_ingress (ctx, & src_id, & trace);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    return ret;\n",
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
int tail_ipv6_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 src_id = 0;
	int ret;

	ret = ipv6_host_policy_ingress(ctx, &src_id, &trace);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
declare_tailcall_if(__or(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
			 is_defined(DEBUG)), CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1432,
  "endLine": 1446,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "tail_ipv4_host_policy_ingress",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int tail_ipv4_host_policy_ingress (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct trace_ctx __maybe_unused trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = TRACE_PAYLOAD_LEN,}\n",
    "    ;\n",
    "    __u32 src_id = 0;\n",
    "    int ret;\n",
    "    ret = ipv4_host_policy_ingress (ctx, & src_id, & trace);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, src_id, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    return ret;\n",
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
int tail_ipv4_host_policy_ingress(struct __ctx_buff *ctx)
{
	struct trace_ctx __maybe_unused trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = TRACE_PAYLOAD_LEN,
	};
	__u32 src_id = 0;
	int ret;

	ret = ipv4_host_policy_ingress(ctx, &src_id, &trace);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, src_id, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	return ret;
}
#endif /* ENABLE_IPV4 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1449,
  "endLine": 1497,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "to_host_from_lxc",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline int to_host_from_lxc (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    __u16 proto = 0;\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    switch (proto) {\n",
    "\n",
    "# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        invoke_tailcall_if (__or (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), is_defined (DEBUG)), CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY, tail_ipv6_host_policy_ingress);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        invoke_tailcall_if (__or (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), is_defined (DEBUG)), CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY, tail_ipv4_host_policy_ingress);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    return ret;\n",
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
static __always_inline int
/* Handles packet from a local endpoint entering the host namespace. Applies
 * ingress host policies.
 */
to_host_from_lxc(struct __ctx_buff *ctx __maybe_unused)
{
	int ret = CTX_ACT_OK;
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV6_TO_HOST_POLICY_ONLY,
				   tail_ipv6_host_policy_ingress);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__or(__and(is_defined(ENABLE_IPV4),
					      is_defined(ENABLE_IPV6)),
					is_defined(DEBUG)),
				   CILIUM_CALL_IPV4_TO_HOST_POLICY_ONLY,
				   tail_ipv4_host_policy_ingress);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      METRIC_INGRESS);
	return ret;
}

/* Handles packets that left the host namespace and will enter a local
 * endpoint's namespace. Applies egress host policies before handling
 * control back to bpf_lxc.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1503,
  "endLine": 1545,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "from_host_to_lxc",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
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
    "static __always_inline int from_host_to_lxc (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    int ret = CTX_ACT_OK;\n",
    "    __u16 proto = 0;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return DROP_UNSUPPORTED_L2;\n",
    "    switch (proto) {\n",
    "\n",
    "# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ret = ipv6_host_policy_egress (ctx, HOST_ID, &trace);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "\n",
    "# ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ret = ipv4_host_policy_egress (ctx, HOST_ID, 0, &trace);\n",
    "        break;\n",
    "\n",
    "# endif\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "    return ret;\n",
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
static __always_inline int
from_host_to_lxc(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	int ret = CTX_ACT_OK;
	__u16 proto = 0;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
# if defined ENABLE_ARP_PASSTHROUGH || defined ENABLE_ARP_RESPONDER
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
# endif
# ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = ipv6_host_policy_egress(ctx, HOST_ID, &trace);
		break;
# endif
# ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		/* The last parameter, ipcache_srcid, is only required when
		 * the src_id is not HOST_ID. For details, see
		 * whitelist_snated_egress_connections.
		 * We only arrive here from bpf_lxc if we know the
		 * src_id is HOST_ID. Therefore, we don't need to pass a value
		 * for the last parameter. That avoids an ipcache lookup.
		 */
		ret = ipv4_host_policy_egress(ctx, HOST_ID, 0, &trace);
		break;
# endif
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

	return ret;
}

/* When per-endpoint routes are enabled, packets to and from local endpoints
 * will tail call into this program to enforce egress and ingress host policies.
 * Packets to the local endpoints will then tail call back to the original
 * bpf_lxc program.
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_HOST_EP_ID)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_dynamicctx",
          " &POLICY_CALL_MAP",
          " lxc_id"
        ]
      }
    ]
  },
  "startLine": 1553,
  "endLine": 1572,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_host.c",
  "funcName": "handle_lxc_traffic",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "int handle_lxc_traffic (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    bool from_host = ctx_load_meta (ctx, CB_FROM_HOST);\n",
    "    __u32 lxc_id;\n",
    "    int ret;\n",
    "    if (from_host) {\n",
    "        ret = from_host_to_lxc (ctx);\n",
    "        if (IS_ERR (ret))\n",
    "            return send_drop_notify_error (ctx, HOST_ID, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "        lxc_id = ctx_load_meta (ctx, CB_DST_ENDPOINT_ID);\n",
    "        ctx_store_meta (ctx, CB_SRC_LABEL, HOST_ID);\n",
    "        tail_call_dynamic (ctx, &POLICY_CALL_MAP, lxc_id);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "    return to_host_from_lxc (ctx);\n",
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
int handle_lxc_traffic(struct __ctx_buff *ctx)
{
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	__u32 lxc_id;
	int ret;

	if (from_host) {
		ret = from_host_to_lxc(ctx);
		if (IS_ERR(ret))
			return send_drop_notify_error(ctx, HOST_ID, ret, CTX_ACT_DROP,
						      METRIC_EGRESS);

		lxc_id = ctx_load_meta(ctx, CB_DST_ENDPOINT_ID);
		ctx_store_meta(ctx, CB_SRC_LABEL, HOST_ID);
		tail_call_dynamic(ctx, &POLICY_CALL_MAP, lxc_id);
		return DROP_MISSED_TAIL_CALL;
	}

	return to_host_from_lxc(ctx);
}
#endif /* ENABLE_HOST_FIREWALL */

BPF_LICENSE("Dual BSD/GPL");