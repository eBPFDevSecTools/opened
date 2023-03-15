/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_L3_H_
#define __LIB_L3_H_

#include "common.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eps.h"
#include "eth.h"
#include "dbg.h"
#include "l4.h"
#include "icmp6.h"
#include "csum.h"

#ifdef ENABLE_IPV6
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
  "startLine": 18,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l3.h",
  "funcName": "ipv6_l3",
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
    },
    {
      "start_line": 28,
      "end_line": 28,
      "text": "/* Hoplimit was reached */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " const __u8 *smac",
    " const __u8 *dmac",
    " __u8 direction"
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
    "static __always_inline int ipv6_l3 (struct  __ctx_buff *ctx, int l3_off, const __u8 *smac, const __u8 *dmac, __u8 direction)\n",
    "{\n",
    "    int ret;\n",
    "    ret = ipv6_dec_hoplimit (ctx, l3_off);\n",
    "    if (IS_ERR (ret))\n",
    "        return ret;\n",
    "    if (ret > 0) {\n",
    "        return icmp6_send_time_exceeded (ctx, l3_off, direction);\n",
    "    }\n",
    "    if (smac && eth_store_saddr (ctx, smac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (dmac && eth_store_daddr (ctx, dmac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "icmp6_send_time_exceeded",
    "eth_store_daddr",
    "ipv6_dec_hoplimit",
    "IS_ERR",
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
static __always_inline int ipv6_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   __u8 direction)
{
	int ret;

	ret = ipv6_dec_hoplimit(ctx, l3_off);
	if (IS_ERR(ret))
		return ret;
	if (ret > 0) {
		/* Hoplimit was reached */
		return icmp6_send_time_exceeded(ctx, l3_off, direction);
	}

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}
#endif /* ENABLE_IPV6 */

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
  "startLine": 41,
  "endLine": 56,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l3.h",
  "funcName": "ipv4_l3",
  "developer_inline_comments": [
    {
      "start_line": 46,
      "end_line": 46,
      "text": "/* FIXME: Send ICMP TTL */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " const __u8 *smac",
    " const __u8 *dmac",
    " struct iphdr *ip4"
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
    "static __always_inline int ipv4_l3 (struct  __ctx_buff *ctx, int l3_off, const __u8 *smac, const __u8 *dmac, struct iphdr *ip4)\n",
    "{\n",
    "    if (ipv4_dec_ttl (ctx, l3_off, ip4)) {\n",
    "        return DROP_INVALID;\n",
    "    }\n",
    "    if (smac && eth_store_saddr (ctx, smac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (dmac && eth_store_daddr (ctx, dmac, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_dec_ttl",
    "eth_store_saddr",
    "eth_store_daddr"
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
static __always_inline int ipv4_l3(struct __ctx_buff *ctx, int l3_off,
				   const __u8 *smac, const __u8 *dmac,
				   struct iphdr *ip4)
{
	if (ipv4_dec_ttl(ctx, l3_off, ip4)) {
		/* FIXME: Send ICMP TTL */
		return DROP_INVALID;
	}

	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
		return DROP_WRITE_ERROR;
	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
		return DROP_WRITE_ERROR;

	return CTX_ACT_OK;
}

#ifndef SKIP_POLICY_MAP
#ifdef ENABLE_IPV6
/* Performs IPv6 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
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
    }
  ],
  "helperCallParams": {},
  "startLine": 65,
  "endLine": 106,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l3.h",
  "funcName": "ipv6_local_delivery",
  "developer_inline_comments": [
    {
      "start_line": 60,
      "end_line": 64,
      "text": "/* Performs IPv6 L2/L3 handling and delivers the packet to the destination pod\n * on the same node, either via the stack or via a redirect call.\n * Depending on the configuration, it may also enforce ingress policies for the\n * destination pod via a tail call.\n */"
    },
    {
      "start_line": 77,
      "end_line": 77,
      "text": "/* This will invalidate the size check */"
    },
    {
      "start_line": 83,
      "end_line": 87,
      "text": "/*\n\t * Special LXC case for updating egress forwarding metrics.\n\t * Note that the packet could still be dropped but it would show up\n\t * as an ingress drop counter in metrics.\n\t */"
    },
    {
      "start_line": 98,
      "end_line": 98,
      "text": "/* Jumps to destination pod's BPF program to enforce ingress policies. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " __u32 seclabel",
    " const struct endpoint_info *ep",
    " __u8 direction",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int ipv6_local_delivery (struct  __ctx_buff *ctx, int l3_off, __u32 seclabel, const struct endpoint_info *ep, __u8 direction, bool from_host __maybe_unused)\n",
    "{\n",
    "    mac_t router_mac = ep->node_mac;\n",
    "    mac_t lxc_mac = ep->mac;\n",
    "    int ret;\n",
    "    cilium_dbg (ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);\n",
    "    ret = ipv6_l3 (ctx, l3_off, (__u8 *) & router_mac, (__u8 *) & lxc_mac, direction);\n",
    "    if (ret != CTX_ACT_OK)\n",
    "        return ret;\n",
    "\n",
    "#ifdef LOCAL_DELIVERY_METRICS\n",
    "    update_metrics (ctx_full_len (ctx), direction, REASON_FORWARDED);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \\\n",
    "\t!defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)\n",
    "    ctx->mark |= MARK_MAGIC_IDENTITY;\n",
    "    set_identity_mark (ctx, seclabel);\n",
    "    return redirect_ep (ctx, ep->ifindex, from_host);\n",
    "\n",
    "#else\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, seclabel);\n",
    "    ctx_store_meta (ctx, CB_IFINDEX, ep->ifindex);\n",
    "    ctx_store_meta (ctx, CB_FROM_HOST, from_host ? 1 : 0);\n",
    "    tail_call_dynamic (ctx, &POLICY_CALL_MAP, ep->lxc_id);\n",
    "    return DROP_MISSED_TAIL_CALL;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "set_identity_mark",
    "ctx_store_meta",
    "ipv6_l3",
    "tail_call_dynamic",
    "defined",
    "ctx_full_len",
    "redirect_ep",
    "cilium_dbg",
    "update_metrics"
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
static __always_inline int ipv6_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel,
					       const struct endpoint_info *ep,
					       __u8 direction,
					       bool from_host __maybe_unused)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	/* This will invalidate the size check */
	ret = ipv6_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, direction);
	if (ret != CTX_ACT_OK)
		return ret;

#ifdef LOCAL_DELIVERY_METRICS
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(ctx_full_len(ctx), direction, REASON_FORWARDED);
#endif

#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \
	!defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)
	ctx->mark |= MARK_MAGIC_IDENTITY;
	set_identity_mark(ctx, seclabel);

	return redirect_ep(ctx, ep->ifindex, from_host);
#else
	/* Jumps to destination pod's BPF program to enforce ingress policies. */
	ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
	ctx_store_meta(ctx, CB_IFINDEX, ep->ifindex);
	ctx_store_meta(ctx, CB_FROM_HOST, from_host ? 1 : 0);

	tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id);
	return DROP_MISSED_TAIL_CALL;
#endif
}
#endif /* ENABLE_IPV6 */

/* Performs IPv4 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
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
    }
  ],
  "helperCallParams": {},
  "startLine": 114,
  "endLine": 154,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l3.h",
  "funcName": "ipv4_local_delivery",
  "developer_inline_comments": [
    {
      "start_line": 109,
      "end_line": 113,
      "text": "/* Performs IPv4 L2/L3 handling and delivers the packet to the destination pod\n * on the same node, either via the stack or via a redirect call.\n * Depending on the configuration, it may also enforce ingress policies for the\n * destination pod via a tail call.\n */"
    },
    {
      "start_line": 131,
      "end_line": 135,
      "text": "/*\n\t * Special LXC case for updating egress forwarding metrics.\n\t * Note that the packet could still be dropped but it would show up\n\t * as an ingress drop counter in metrics.\n\t */"
    },
    {
      "start_line": 146,
      "end_line": 146,
      "text": "/* Jumps to destination pod's BPF program to enforce ingress policies. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " __u32 seclabel",
    " struct iphdr *ip4",
    " const struct endpoint_info *ep",
    " __u8 direction __maybe_unused",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int ipv4_local_delivery (struct  __ctx_buff *ctx, int l3_off, __u32 seclabel, struct iphdr *ip4, const struct endpoint_info *ep, __u8 direction __maybe_unused, bool from_host __maybe_unused)\n",
    "{\n",
    "    mac_t router_mac = ep->node_mac;\n",
    "    mac_t lxc_mac = ep->mac;\n",
    "    int ret;\n",
    "    cilium_dbg (ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);\n",
    "    ret = ipv4_l3 (ctx, l3_off, (__u8 *) & router_mac, (__u8 *) & lxc_mac, ip4);\n",
    "    if (ret != CTX_ACT_OK)\n",
    "        return ret;\n",
    "\n",
    "#ifdef LOCAL_DELIVERY_METRICS\n",
    "    update_metrics (ctx_full_len (ctx), direction, REASON_FORWARDED);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \\\n",
    "\t!defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)\n",
    "    ctx->mark |= MARK_MAGIC_IDENTITY;\n",
    "    set_identity_mark (ctx, seclabel);\n",
    "    return redirect_ep (ctx, ep->ifindex, from_host);\n",
    "\n",
    "#else\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, seclabel);\n",
    "    ctx_store_meta (ctx, CB_IFINDEX, ep->ifindex);\n",
    "    ctx_store_meta (ctx, CB_FROM_HOST, from_host ? 1 : 0);\n",
    "    tail_call_dynamic (ctx, &POLICY_CALL_MAP, ep->lxc_id);\n",
    "    return DROP_MISSED_TAIL_CALL;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "set_identity_mark",
    "ctx_store_meta",
    "tail_call_dynamic",
    "defined",
    "ipv4_l3",
    "ctx_full_len",
    "redirect_ep",
    "cilium_dbg",
    "update_metrics"
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
static __always_inline int ipv4_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, struct iphdr *ip4,
					       const struct endpoint_info *ep,
					       __u8 direction __maybe_unused,
					       bool from_host __maybe_unused)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

#ifdef LOCAL_DELIVERY_METRICS
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(ctx_full_len(ctx), direction, REASON_FORWARDED);
#endif

#if defined(USE_BPF_PROG_FOR_INGRESS_POLICY) && \
	!defined(FORCE_LOCAL_POLICY_EVAL_AT_SOURCE)
	ctx->mark |= MARK_MAGIC_IDENTITY;
	set_identity_mark(ctx, seclabel);

	return redirect_ep(ctx, ep->ifindex, from_host);
#else
	/* Jumps to destination pod's BPF program to enforce ingress policies. */
	ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
	ctx_store_meta(ctx, CB_IFINDEX, ep->ifindex);
	ctx_store_meta(ctx, CB_FROM_HOST, from_host ? 1 : 0);

	tail_call_dynamic(ctx, &POLICY_CALL_MAP, ep->lxc_id);
	return DROP_MISSED_TAIL_CALL;
#endif
}
#endif /* SKIP_POLICY_MAP */

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
  "startLine": 157,
  "endLine": 185,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l3.h",
  "funcName": "get_min_encrypt_key",
  "developer_inline_comments": [
    {
      "start_line": 165,
      "end_line": 165,
      "text": "/* Having no key info for a context is the same as no encryption */"
    },
    {
      "start_line": 169,
      "end_line": 176,
      "text": "/* If both ends can encrypt/decrypt use smaller of the two this\n\t * way both ends will have keys installed assuming key IDs are\n\t * always increasing. However, we have to handle roll-over case\n\t * and to do this safely we assume keys are no more than one ahead.\n\t * We expect user/control-place to accomplish this. Notice zero\n\t * will always be returned if either local or peer have the zero\n\t * key indicating no encryption.\n\t */"
    },
    {
      "start_line": 184,
      "end_line": 184,
      "text": "/* ENABLE_IPSEC */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  ENCRYPT_MAP"
  ],
  "input": [
    "__u8 peer_key __maybe_unused"
  ],
  "output": "static__always_inline__u8",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u8 get_min_encrypt_key (__u8 peer_key __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    __u8 local_key = 0;\n",
    "    __u32 encrypt_key = 0;\n",
    "    struct encrypt_config *cfg;\n",
    "    cfg = map_lookup_elem (& ENCRYPT_MAP, & encrypt_key);\n",
    "    if (cfg)\n",
    "        local_key = cfg->encrypt_key;\n",
    "    if (peer_key == MAX_KEY_INDEX)\n",
    "        return local_key == 1 ? peer_key : local_key;\n",
    "    if (local_key == MAX_KEY_INDEX)\n",
    "        return peer_key == 1 ? local_key : peer_key;\n",
    "    return local_key < peer_key ? local_key : peer_key;\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif /* ENABLE_IPSEC */\n",
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
static __always_inline __u8 get_min_encrypt_key(__u8 peer_key __maybe_unused)
{
#ifdef ENABLE_IPSEC
	__u8 local_key = 0;
	__u32 encrypt_key = 0;
	struct encrypt_config *cfg;

	cfg = map_lookup_elem(&ENCRYPT_MAP, &encrypt_key);
	/* Having no key info for a context is the same as no encryption */
	if (cfg)
		local_key = cfg->encrypt_key;

	/* If both ends can encrypt/decrypt use smaller of the two this
	 * way both ends will have keys installed assuming key IDs are
	 * always increasing. However, we have to handle roll-over case
	 * and to do this safely we assume keys are no more than one ahead.
	 * We expect user/control-place to accomplish this. Notice zero
	 * will always be returned if either local or peer have the zero
	 * key indicating no encryption.
	 */
	if (peer_key == MAX_KEY_INDEX)
		return local_key == 1 ? peer_key : local_key;
	if (local_key == MAX_KEY_INDEX)
		return peer_key == 1 ? local_key : peer_key;
	return local_key < peer_key ? local_key : peer_key;
#else
	return 0;
#endif /* ENABLE_IPSEC */
}

#endif
