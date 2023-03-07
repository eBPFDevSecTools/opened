// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <ep_config.h>
#include <node_config.h>

#include <bpf/verifier.h>

#include <linux/icmpv6.h>

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

#define EVENT_SOURCE LXC_ID

#include "lib/tailcall.h"
#include "lib/common.h"
#include "lib/config.h"
#include "lib/maps.h"
#include "lib/arp.h"
#include "lib/edt.h"
#include "lib/qm.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/l3.h"
#include "lib/lxc.h"
#include "lib/identity.h"
#include "lib/policy.h"

/* Override LB_SELECTION initially defined in node_config.h to force bpf_lxc to use the random backend selection
 * algorithm for in-cluster traffic. Otherwise, it will fail with the Maglev hash algorithm because Cilium doesn't provision
 * the Maglev table for ClusterIP unless bpf.lbExternalClusterIP is set to true.
 */
#undef LB_SELECTION
#define LB_SELECTION LB_SELECTION_RANDOM

#include "lib/lb.h"
#include "lib/drop.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/csum.h"
#include "lib/egress_policies.h"
#include "lib/encap.h"
#include "lib/eps.h"
#include "lib/nat.h"
#include "lib/fib.h"
#include "lib/nodeport.h"
#include "lib/policy_log.h"

/* Per-packet LB is needed if all LB cases can not be handled in bpf_sock.
 * Most services with L7 LB flag can not be redirected to their proxy port
 * in bpf_sock, so we must check for those via per packet LB as well.
 */
#if !defined(ENABLE_SOCKET_LB_FULL) || \
    defined(ENABLE_SOCKET_LB_HOST_ONLY) || \
    defined(ENABLE_L7_LB)
# define ENABLE_PER_PACKET_LB 1
#endif

#if defined(ENABLE_ARP_PASSTHROUGH) && defined(ENABLE_ARP_RESPONDER)
#error "Either ENABLE_ARP_PASSTHROUGH or ENABLE_ARP_RESPONDER can be defined"
#endif

/* Before upstream commit d71962f3e627 (4.18), map helpers were not
 * allowed to access map values directly. So for those older kernels,
 * we need to copy the data to the stack first.
 * We don't have a probe for that, but the bpf_fib_lookup helper was
 * introduced in the same release.
 */
#define HAVE_DIRECT_ACCESS_TO_MAP_VALUES \
    HAVE_PROG_TYPE_HELPER(sched_cls, bpf_fib_lookup)

#define TAIL_CT_LOOKUP4(ID, NAME, DIR, CONDITION, TARGET_ID, TARGET_NAME)	\
declare_tailcall_if(CONDITION, ID)						\
int NAME(struct __ctx_buff *ctx)						\
{										\
	struct ct_buffer4 ct_buffer = {};					\
	int l4_off, ret = CTX_ACT_OK;						\
	struct ipv4_ct_tuple *tuple;						\
	struct ct_state *ct_state;						\
	void *data, *data_end;							\
	struct iphdr *ip4;							\
	__u32 zero = 0;								\
										\
	ct_state = (struct ct_state *)&ct_buffer.ct_state;			\
	tuple = (struct ipv4_ct_tuple *)&ct_buffer.tuple;			\
										\
	if (!revalidate_data(ctx, &data, &data_end, &ip4))			\
		return DROP_INVALID;						\
										\
	tuple->nexthdr = ip4->protocol;						\
	tuple->daddr = ip4->daddr;						\
	tuple->saddr = ip4->saddr;						\
										\
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);					\
										\
	ct_buffer.ret = ct_lookup4(get_ct_map4(tuple), tuple, ctx, l4_off,	\
				   DIR, ct_state, &ct_buffer.monitor);		\
	if (ct_buffer.ret < 0)							\
		return ct_buffer.ret;						\
										\
	if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) < 0)	\
		return DROP_INVALID_TC_BUFFER;					\
										\
	invoke_tailcall_if(CONDITION, TARGET_ID, TARGET_NAME);			\
	return ret;								\
}

#define TAIL_CT_LOOKUP6(ID, NAME, DIR, CONDITION, TARGET_ID, TARGET_NAME)	\
declare_tailcall_if(CONDITION, ID)						\
int NAME(struct __ctx_buff *ctx)						\
{										\
	int l4_off, ret = CTX_ACT_OK, hdrlen;					\
	struct ct_buffer6 ct_buffer = {};					\
	struct ipv6_ct_tuple *tuple;						\
	struct ct_state *ct_state;						\
	void *data, *data_end;							\
	struct ipv6hdr *ip6;							\
	__u32 zero = 0;								\
										\
	ct_state = (struct ct_state *)&ct_buffer.ct_state;			\
	tuple = (struct ipv6_ct_tuple *)&ct_buffer.tuple;			\
										\
	if (!revalidate_data(ctx, &data, &data_end, &ip6))			\
		return DROP_INVALID;						\
										\
	tuple->nexthdr = ip6->nexthdr;						\
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);		\
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);		\
										\
	hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);				\
	if (hdrlen < 0)								\
		return hdrlen;							\
										\
	l4_off = ETH_HLEN + hdrlen;						\
										\
	ct_buffer.ret = ct_lookup6(get_ct_map6(tuple), tuple, ctx, l4_off,	\
				   DIR, ct_state, &ct_buffer.monitor);		\
	if (ct_buffer.ret < 0)							\
		return ct_buffer.ret;						\
										\
	if (map_update_elem(&CT_TAIL_CALL_BUFFER6, &zero, &ct_buffer, 0) < 0)	\
		return DROP_INVALID_TC_BUFFER;					\
										\
	invoke_tailcall_if(CONDITION, TARGET_ID, TARGET_NAME);			\
	return ret;								\
}

#if defined(ENABLE_IPV4) || defined(ENABLE_IPV6)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "_to_proxyint verdict",
          " enum ct_status status"
        ]
      }
    ]
  },
  "startLine": 157,
  "endLine": 162,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "redirect_to_proxy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int verdict",
    " enum ct_status status"
  ],
  "output": "static__always_inlinebool",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "static __always_inline bool redirect_to_proxy (int verdict, enum ct_status status)\n",
    "{\n",
    "    return is_defined (ENABLE_HOST_REDIRECT) && verdict > 0 && (status == CT_NEW || status == CT_ESTABLISHED || status == CT_REOPENED);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline bool
redirect_to_proxy(int verdict, enum ct_status status)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (status == CT_NEW || status == CT_ESTABLISHED ||  status == CT_REOPENED);
}
#endif

#ifdef ENABLE_CUSTOM_CALLS
/* Encode return value and identity into cb buffer. This is used before
 * executing tail calls to custom programs. "ret" is the return value supposed
 * to be returned to the kernel, needed by the callee to preserve the datapath
 * logics. The "identity" is the security identity of the local endpoint: the
 * source of the packet on ingress path, or its destination on the egress path.
 * We encode it so that custom programs can retrieve it and use it at their
 * convenience.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 174,
  "endLine": 189,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "encode_custom_prog_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int ret",
    " __u32 identity"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline int encode_custom_prog_meta (struct  __ctx_buff *ctx, int ret, __u32 identity)\n",
    "{\n",
    "    __u32 custom_meta = 0;\n",
    "    if ((ret & 0xff) != ret)\n",
    "        return -1;\n",
    "    custom_meta |= (__u32) (ret & 0xff) << 24;\n",
    "    custom_meta |= (identity & 0xffffff);\n",
    "    ctx_store_meta (ctx, CB_CUSTOM_CALLS, custom_meta);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int
encode_custom_prog_meta(struct __ctx_buff *ctx, int ret, __u32 identity)
{
	__u32 custom_meta = 0;

	/* If we cannot encode return value on 8 bits, return an error so we can
	 * skip the tail call entirely, as custom program has no way to return
	 * expected value and datapath logics will break.
	 */
	if ((ret & 0xff) != ret)
		return -1;
	custom_meta |= (__u32)(ret & 0xff) << 24;
	custom_meta |= (identity & 0xffffff);
	ctx_store_meta(ctx, CB_CUSTOM_CALLS, custom_meta);
	return 0;
}
#endif

#ifdef ENABLE_IPV6
struct ct_buffer6 {
	struct ipv6_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer6);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER6 __section_maps_btf;

/* Handle egress IPv6 traffic from a container after service translation has been done
 * either at the socket level or by the caller.
 * In the case of the caller doing the service translation it passes in state via CB,
 * which we take in with lb6_ctx_restore_state().
 *
 * Kernel 4.9 verifier is very finicky about the order of this code, modify with caution.
 */
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
    "map_lookup_elem": [
      {
        "opVar": "\t#endif \tct_buffer ",
        "inpVar": [
          " &CT_TAIL_CALL_BUFFER6",
          " &zero"
        ]
      }
    ],
    "redirect": [
      {
        "opVar": "\t#endif \t\tif ((ct_status ",
        "inpVar": [
          ""
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t\treturn ctx__to_proxy6ctx",
          " tuple",
          " 0",
          " false"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif !from_l7lb && _to_proxyverdict",
          " ct_status "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\treturn ctx__to_proxy6ctx",
          " tuple",
          " proxy_port",
          " false"
        ]
      },
      {
        "opVar": "\t\t\t\tret ",
        "inpVar": [
          " encap_and__lxcctx",
          " tunnel_endpoint",
          " encrypt_key",
          "\t\t\t\t\t     &key",
          " SECLABEL",
          " &trace"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t#endif\tif is_definedENABLE_HOST_ROUTING\t\treturn _direct_v6ctx",
          " ETH_HLEN",
          " ip6"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\treturn ctx_ctx",
          " HOST_IFINDEX",
          " BPF_F_INGRESS"
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_IPV6_NODEPORT_REVNAT"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &POLICY_CALL_MAP",
          " HOST_EP_ID"
        ]
      }
    ]
  },
  "startLine": 214,
  "endLine": 581,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_ipv6_from_lxc",
  "updateMaps": [],
  "readMaps": [
    "  CT_TAIL_CALL_BUFFER6"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 *dst_id"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call",
    "redirect",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "static __always_inline int handle_ipv6_from_lxc (struct  __ctx_buff *ctx, __u32 *dst_id)\n",
    "{\n",
    "    struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};\n",
    "    struct ipv6_ct_tuple tuple_on_stack __maybe_unused, *tuple;\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "    union macaddr router_mac = NODE_MAC;\n",
    "\n",
    "#endif\n",
    "    struct ct_buffer6 *ct_buffer;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ret, verdict = 0, l4_off, hdrlen, zero = 0;\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u32 __maybe_unused tunnel_endpoint = 0;\n",
    "    __u8 __maybe_unused encrypt_key = 0;\n",
    "    enum ct_status ct_status;\n",
    "    bool hairpin_flow = false;\n",
    "    __u8 policy_match_type = POLICY_MATCH_NONE;\n",
    "    __u8 audited = 0;\n",
    "    bool __maybe_unused dst_remote_ep = false;\n",
    "    __u16 proxy_port = 0;\n",
    "    bool from_l7lb = false;\n",
    "    bool emit_policy_verdict = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    if (1) {\n",
    "        const union v6addr *daddr = (union v6addr *) &ip6->daddr;\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = lookup_ip6_remote_endpoint (daddr);\n",
    "        if (info && info->sec_label) {\n",
    "            *dst_id = info->sec_label;\n",
    "            tunnel_endpoint = info->tunnel_endpoint;\n",
    "            encrypt_key = get_min_encrypt_key (info -> key);\n",
    "\n",
    "#ifdef ENABLE_WIREGUARD\n",
    "            if (info->tunnel_endpoint != 0 && !identity_is_node (info->sec_label))\n",
    "                dst_remote_ep = true;\n",
    "\n",
    "#endif /* ENABLE_WIREGUARD */\n",
    "        }\n",
    "        else {\n",
    "            *dst_id = WORLD_ID;\n",
    "        }\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6, daddr->p4, *dst_id);\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_PER_PACKET_LB\n",
    "\n",
    "#if !defined(DEBUG) && defined(TUNNEL_MODE)\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "\n",
    "#endif\n",
    "    lb6_ctx_restore_state (ctx, &ct_state_new, &proxy_port);\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB */\n",
    "    ct_buffer = map_lookup_elem (& CT_TAIL_CALL_BUFFER6, & zero);\n",
    "    if (!ct_buffer)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "    if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "\n",
    "#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES\n",
    "    tuple = (struct ipv6_ct_tuple *) &ct_buffer->tuple;\n",
    "    ct_state = (struct ct_state *) &ct_buffer->ct_state;\n",
    "\n",
    "#else\n",
    "    memcpy (&tuple_on_stack, &ct_buffer->tuple, sizeof (tuple_on_stack));\n",
    "    tuple = &tuple_on_stack;\n",
    "    memcpy (&ct_state_on_stack, &ct_buffer->ct_state, sizeof (ct_state_on_stack));\n",
    "    ct_state = &ct_state_on_stack;\n",
    "\n",
    "#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */\n",
    "    trace.monitor = ct_buffer->monitor;\n",
    "    ret = ct_buffer->ret;\n",
    "    ct_status = (enum ct_status) ret;\n",
    "    trace.reason = (enum trace_reason) ret;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    if (proxy_port > 0) {\n",
    "        cilium_dbg3 (ctx, DBG_L7_LB, tuple->daddr.p4, tuple->saddr.p4, bpf_ntohs (proxy_port));\n",
    "        verdict = proxy_port;\n",
    "        emit_policy_verdict = false;\n",
    "        goto skip_policy_enforcement;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "    if ((ct_status == CT_REPLY || ct_status == CT_RELATED) && ct_state->proxy_redirect) {\n",
    "        return ctx_redirect_to_proxy6 (ctx, tuple, 0, false);\n",
    "    }\n",
    "    if (hairpin_flow) {\n",
    "        emit_policy_verdict = false;\n",
    "        goto skip_policy_enforcement;\n",
    "    }\n",
    "    verdict = policy_can_egress6 (ctx, tuple, SECLABEL, * dst_id, & policy_match_type, & audited);\n",
    "    if (ct_status != CT_REPLY && ct_status != CT_RELATED && verdict < 0) {\n",
    "        send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 1, verdict, policy_match_type, audited);\n",
    "        return verdict;\n",
    "    }\n",
    "skip_policy_enforcement :\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    from_l7lb = ctx_load_meta (ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;\n",
    "\n",
    "#endif\n",
    "    switch (ct_status) {\n",
    "    case CT_NEW :\n",
    "        if (emit_policy_verdict)\n",
    "            send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 1, verdict, policy_match_type, audited);\n",
    "    ct_recreate6 :\n",
    "        ct_state_new.src_sec_id = SECLABEL;\n",
    "        ret = ct_create6 (get_ct_map6 (tuple), & CT_MAP_ANY6, tuple, ctx, CT_EGRESS, & ct_state_new, verdict > 0, from_l7lb);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        trace.monitor = TRACE_PAYLOAD_LEN;\n",
    "        break;\n",
    "    case CT_REOPENED :\n",
    "        if (emit_policy_verdict)\n",
    "            send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 1, verdict, policy_match_type, audited);\n",
    "    case CT_ESTABLISHED :\n",
    "        if (unlikely (ct_state->rev_nat_index != ct_state_new.rev_nat_index))\n",
    "            goto ct_recreate6;\n",
    "        break;\n",
    "    case CT_RELATED :\n",
    "    case CT_REPLY :\n",
    "        policy_mark_skip (ctx);\n",
    "        hdrlen = ipv6_hdrlen (ctx, & tuple -> nexthdr);\n",
    "        if (hdrlen < 0)\n",
    "            return hdrlen;\n",
    "        l4_off = ETH_HLEN + hdrlen;\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "\n",
    "# ifdef ENABLE_DSR\n",
    "        if (ct_state->dsr) {\n",
    "            ret = xlate_dsr_v6 (ctx, tuple, l4_off);\n",
    "            if (ret != 0)\n",
    "                return ret;\n",
    "        }\n",
    "        else\n",
    "\n",
    "# endif /* ENABLE_DSR */\n",
    "            if (ct_state->node_port) {\n",
    "                send_trace_notify (ctx, TRACE_TO_NETWORK, SECLABEL, *dst_id, 0, 0, trace.reason, trace.monitor);\n",
    "                ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;\n",
    "                ep_tail_call (ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);\n",
    "                return DROP_MISSED_TAIL_CALL;\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "        if (ct_state->rev_nat_index) {\n",
    "            struct csum_offset csum_off = {}\n",
    "            ;\n",
    "            csum_l4_offset_and_flags (tuple->nexthdr, &csum_off);\n",
    "            ret = lb6_rev_nat (ctx, l4_off, & csum_off, ct_state -> rev_nat_index, tuple, 0);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "            policy_mark_skip (ctx);\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_CT;\n",
    "    }\n",
    "    hairpin_flow |= ct_state->loopback;\n",
    "    if (!from_l7lb && redirect_to_proxy (verdict, ct_status)) {\n",
    "        proxy_port = (__u16) verdict;\n",
    "        send_trace_notify (ctx, TRACE_TO_PROXY, SECLABEL, 0, bpf_ntohs (proxy_port), 0, trace.reason, trace.monitor);\n",
    "        return ctx_redirect_to_proxy6 (ctx, tuple, proxy_port, false);\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    if (is_defined (ENABLE_ROUTING) || hairpin_flow) {\n",
    "        struct endpoint_info *ep;\n",
    "        ep = lookup_ip6_endpoint (ip6);\n",
    "        if (ep) {\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "            if (ep->flags & ENDPOINT_F_HOST) {\n",
    "\n",
    "#ifdef HOST_IFINDEX\n",
    "                goto to_host;\n",
    "\n",
    "#else\n",
    "                return DROP_HOST_UNREACHABLE;\n",
    "\n",
    "#endif\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_ROUTING */\n",
    "            policy_clear_mark (ctx);\n",
    "            return ipv6_local_delivery (ctx, ETH_HLEN, SECLABEL, ep, METRIC_EGRESS, from_l7lb);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)\n",
    "    if (*dst_id == HOST_ID) {\n",
    "        ctx_store_meta (ctx, CB_FROM_HOST, 0);\n",
    "        tail_call_static (ctx, &POLICY_CALL_MAP, HOST_EP_ID);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "\n",
    "# ifdef ENABLE_WIREGUARD\n",
    "    if (!dst_remote_ep)\n",
    "\n",
    "# endif /* ENABLE_WIREGUARD */\n",
    "        {\n",
    "            struct endpoint_key key = {}\n",
    "            ;\n",
    "            union v6addr *daddr = (union v6addr *) &ip6->daddr;\n",
    "            key.ip6.p1 = daddr->p1;\n",
    "            key.ip6.p2 = daddr->p2;\n",
    "            key.ip6.p3 = daddr->p3;\n",
    "            key.family = ENDPOINT_KEY_IPV6;\n",
    "            ret = encap_and_redirect_lxc (ctx, tunnel_endpoint, encrypt_key, & key, SECLABEL, & trace);\n",
    "            if (ret == IPSEC_ENDPOINT)\n",
    "                goto encrypt_to_stack;\n",
    "            else if (ret != DROP_NO_TUNNEL_ENDPOINT)\n",
    "                return ret;\n",
    "        }\n",
    "\n",
    "#endif\n",
    "    if (is_defined (ENABLE_HOST_ROUTING))\n",
    "        return redirect_direct_v6 (ctx, ETH_HLEN, ip6);\n",
    "    goto pass_to_stack;\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "to_host :\n",
    "    if (is_defined (ENABLE_HOST_FIREWALL) && *dst_id == HOST_ID) {\n",
    "        send_trace_notify (ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0, HOST_IFINDEX, trace.reason, trace.monitor);\n",
    "        return ctx_redirect (ctx, HOST_IFINDEX, BPF_F_INGRESS);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "pass_to_stack :\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "    ret = ipv6_l3 (ctx, ETH_HLEN, NULL, (__u8 *) & router_mac.addr, METRIC_EGRESS);\n",
    "    if (unlikely (ret != CTX_ACT_OK))\n",
    "        return ret;\n",
    "\n",
    "#endif\n",
    "    if (ipv6_store_flowlabel (ctx, ETH_HLEN, SECLABEL_NB) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "\n",
    "#ifdef ENABLE_WIREGUARD\n",
    "    if (dst_remote_ep)\n",
    "        set_encrypt_mark (ctx);\n",
    "    else\n",
    "\n",
    "#elif !defined(TUNNEL_MODE)\n",
    "\n",
    "# ifdef ENABLE_IPSEC\n",
    "        if (encrypt_key && tunnel_endpoint) {\n",
    "            set_encrypt_key_mark (ctx, encrypt_key);\n",
    "\n",
    "#  ifdef IP_POOLS\n",
    "            set_encrypt_dip (ctx, tunnel_endpoint);\n",
    "\n",
    "#  endif /* IP_POOLS */\n",
    "\n",
    "#  ifdef ENABLE_IDENTITY_MARK\n",
    "            set_identity_mark (ctx, SECLABEL);\n",
    "\n",
    "#  endif /* ENABLE_IDENTITY_MARK */\n",
    "        }\n",
    "        else\n",
    "\n",
    "# endif /* ENABLE_IPSEC */\n",
    "\n",
    "#endif /* ENABLE_WIREGUARD */\n",
    "            {\n",
    "\n",
    "#ifdef ENABLE_IDENTITY_MARK\n",
    "                ctx->mark |= MARK_MAGIC_IDENTITY;\n",
    "                set_identity_mark (ctx, SECLABEL);\n",
    "\n",
    "#endif\n",
    "            }\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "encrypt_to_stack :\n",
    "\n",
    "#endif\n",
    "    send_trace_notify (ctx, TRACE_TO_STACK, SECLABEL, *dst_id, 0, 0, trace.reason, trace.monitor);\n",
    "    cilium_dbg_capture (ctx, DBG_CAPTURE_DELIVERY, 0);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int handle_ipv6_from_lxc(struct __ctx_buff *ctx, __u32 *dst_id)
{
	struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};
	struct ipv6_ct_tuple tuple_on_stack __maybe_unused, *tuple;
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	struct ct_buffer6 *ct_buffer;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, verdict = 0, l4_off, hdrlen, zero = 0;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 __maybe_unused tunnel_endpoint = 0;
	__u8 __maybe_unused encrypt_key = 0;
	enum ct_status ct_status;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool __maybe_unused dst_remote_ep = false;
	__u16 proxy_port = 0;
	bool from_l7lb = false;
	bool emit_policy_verdict = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Determine the destination category for policy fallback.  Service
	 * translation of the destination address is done before this function,
	 * so we can do this first. Also, verifier on kernel 4.9 insisted this
	 * be done before the CT lookup below.
	 */
	if (1) {
		const union v6addr *daddr = (union v6addr *)&ip6->daddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(daddr);
		if (info && info->sec_label) {
			*dst_id = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
#ifdef ENABLE_WIREGUARD
			if (info->tunnel_endpoint != 0 &&
			    !identity_is_node(info->sec_label))
				dst_remote_ep = true;
#endif /* ENABLE_WIREGUARD */
		} else {
			*dst_id = WORLD_ID;
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   daddr->p4, *dst_id);
	}

#ifdef ENABLE_PER_PACKET_LB
#if !defined(DEBUG) && defined(TUNNEL_MODE)
	/* verifier workaround on kernel 4.9, not needed otherwise */
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
#endif
	/* Restore ct_state from per packet lb handling in the previous tail call. */
	lb6_ctx_restore_state(ctx, &ct_state_new, &proxy_port);
	/* No hairpin/loopback support for IPv6, see lb6_local(). */
#endif /* ENABLE_PER_PACKET_LB */

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES
	tuple = (struct ipv6_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
#else
	memcpy(&tuple_on_stack, &ct_buffer->tuple, sizeof(tuple_on_stack));
	tuple = &tuple_on_stack;
	memcpy(&ct_state_on_stack, &ct_buffer->ct_state, sizeof(ct_state_on_stack));
	ct_state = &ct_state_on_stack;
#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */
	trace.monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	ct_status = (enum ct_status)ret;
	trace.reason = (enum trace_reason)ret;

#if defined(ENABLE_L7_LB)
	if (proxy_port > 0) {
		/* tuple addresses have been swapped by CT lookup */
		cilium_dbg3(ctx, DBG_L7_LB, tuple->daddr.p4, tuple->saddr.p4,
			    bpf_ntohs(proxy_port));
		verdict = proxy_port;
		emit_policy_verdict = false;
		goto skip_policy_enforcement;
	}
#endif /* ENABLE_L7_LB */

	/* Check it this is return traffic to an ingress proxy. */
	if ((ct_status == CT_REPLY || ct_status == CT_RELATED) &&
	    ct_state->proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
		return ctx_redirect_to_proxy6(ctx, tuple, 0, false);
	}

	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (hairpin_flow) {
		emit_policy_verdict = false;
		goto skip_policy_enforcement;
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress6(ctx, tuple, SECLABEL, *dst_id,
				     &policy_match_type, &audited);

	if (ct_status != CT_REPLY && ct_status != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

skip_policy_enforcement:
#if defined(ENABLE_L7_LB)
	from_l7lb = ctx_load_meta(ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;
#endif
	switch (ct_status) {
	case CT_NEW:
		if (emit_policy_verdict)
			send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 1,
						   verdict, policy_match_type, audited);
ct_recreate6:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0, from_l7lb);
		if (IS_ERR(ret))
			return ret;
		trace.monitor = TRACE_PAYLOAD_LEN;
		break;

	case CT_REOPENED:
		if (emit_policy_verdict)
			send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 1,
						   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state->rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate6;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

		hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		l4_off = ETH_HLEN + hdrlen;

#ifdef ENABLE_NODEPORT
# ifdef ENABLE_DSR
		if (ct_state->dsr) {
			ret = xlate_dsr_v6(ctx, tuple, l4_off);
			if (ret != 0)
				return ret;
		} else
# endif /* ENABLE_DSR */
		/* See comment in handle_ipv4_from_lxc(). */
		if (ct_state->node_port) {
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL,
					  *dst_id, 0, 0,
					  trace.reason, trace.monitor);
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV6_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}
#endif /* ENABLE_NODEPORT */

		if (ct_state->rev_nat_index) {
			struct csum_offset csum_off = {};

			csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);
			ret = lb6_rev_nat(ctx, l4_off, &csum_off,
					  ct_state->rev_nat_index, tuple, 0);
			if (IS_ERR(ret))
				return ret;

			/* A reverse translate packet is always allowed except
			 * for delivery on the local node in which case this
			 * marking is cleared again.
			 */
			policy_mark_skip(ctx);
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state->loopback;

	/* L7 LB does L7 policy enforcement, so we only redirect packets
	 * NOT from L7 LB.
	 */
	if (!from_l7lb && redirect_to_proxy(verdict, ct_status)) {
		proxy_port = (__u16)verdict;
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  bpf_ntohs(proxy_port), 0,
				  trace.reason, trace.monitor);
		return ctx_redirect_to_proxy6(ctx, tuple, proxy_port, false);
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* See handle_ipv4_from_lxc() re hairpin_flow */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv6 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint managed by
		 *    cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself.
		 */
		ep = lookup_ip6_endpoint(ip6);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
			/* If the packet is from L7 LB it is coming from the host */
			return ipv6_local_delivery(ctx, ETH_HLEN, SECLABEL, ep,
						   METRIC_EGRESS, from_l7lb);
		}
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 */
	if (*dst_id == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	/* The packet goes to a peer not managed by this agent instance */
#ifdef TUNNEL_MODE
# ifdef ENABLE_WIREGUARD
	if (!dst_remote_ep)
# endif /* ENABLE_WIREGUARD */
	{
		struct endpoint_key key = {};
		union v6addr *daddr = (union v6addr *)&ip6->daddr;

		/* Lookup the destination prefix in the list of known
		 * destination prefixes. If there is a match, the packet will
		 * be encapsulated to that node and then routed by the agent on
		 * the remote node.
		 *
		 * IPv6 lookup key: daddr/96
		 */
		key.ip6.p1 = daddr->p1;
		key.ip6.p2 = daddr->p2;
		key.ip6.p3 = daddr->p3;
		key.family = ENDPOINT_KEY_IPV6;

		/* Three cases exist here either (a) the encap and redirect could
		 * not find the tunnel so fallthrough to nat46 and stack, (b)
		 * the packet needs IPSec encap so push ctx to stack for encap, or
		 * (c) packet was redirected to tunnel device so return.
		 */
		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
					     &key, SECLABEL, &trace);
		if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		else if (ret != DROP_NO_TUNNEL_ENDPOINT)
			return ret;
	}
#endif
	if (is_defined(ENABLE_HOST_ROUTING))
		return redirect_direct_v6(ctx, ETH_HLEN, ip6);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_FIREWALL) && *dst_id == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, trace.reason, trace.monitor);
		return ctx_redirect(ctx, HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv6_l3(ctx, ETH_HLEN, NULL, (__u8 *)&router_mac.addr, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

	if (ipv6_store_flowlabel(ctx, ETH_HLEN, SECLABEL_NB) < 0)
		return DROP_WRITE_ERROR;

#ifdef ENABLE_WIREGUARD
	if (dst_remote_ep)
		set_encrypt_mark(ctx);
	else
#elif !defined(TUNNEL_MODE)
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#  ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#  endif /* IP_POOLS */
#  ifdef ENABLE_IDENTITY_MARK
		set_identity_mark(ctx, SECLABEL);
#  endif /* ENABLE_IDENTITY_MARK */
	} else
# endif /* ENABLE_IPSEC */
#endif /* ENABLE_WIREGUARD */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#ifdef TUNNEL_MODE
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dst_id, 0, 0,
			  trace.reason, trace.monitor);

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);

	return CTX_ACT_OK;
}

declare_tailcall_if(is_defined(ENABLE_PER_PACKET_LB), CILIUM_CALL_IPV6_FROM_LXC_CONT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV6_EGRESS"
        ]
      }
    ]
  },
  "startLine": 584,
  "endLine": 603,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_handle_ipv6_cont",
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
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int tail_handle_ipv6_cont (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 dst_id = 0;\n",
    "    int ret = handle_ipv6_from_lxc (ctx, & dst_id);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, SECLABEL, dst_id, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!encode_custom_prog_meta (ctx, ret, dst_id)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV6_EGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_EGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_handle_ipv6_cont(struct __ctx_buff *ctx)
{
	__u32 dst_id = 0;
	int ret = handle_ipv6_from_lxc(ctx, &dst_id);

	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, dst_id, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dst_id)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_EGRESS, tail_ipv6_ct_egress, CT_EGRESS,
		is_defined(ENABLE_PER_PACKET_LB),
		CILIUM_CALL_IPV6_FROM_LXC_CONT, tail_handle_ipv6_cont)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 609,
  "endLine": 694,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "__tail_handle_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline int __tail_handle_ipv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ret;\n",
    "    if (!revalidate_data_pull (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    if (unlikely (ip6->nexthdr == IPPROTO_ICMPV6)) {\n",
    "        if (data + sizeof (*ip6) + ETH_HLEN + sizeof (struct icmp6hdr) > data_end)\n",
    "            return DROP_INVALID;\n",
    "        ret = icmp6_handle (ctx, ETH_HLEN, ip6, METRIC_EGRESS);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (unlikely (!is_valid_lxc_src_ip (ip6)))\n",
    "        return DROP_INVALID_SIP;\n",
    "\n",
    "#ifdef ENABLE_PER_PACKET_LB\n",
    "    {\n",
    "        struct ipv6_ct_tuple tuple = {}\n",
    "        ;\n",
    "        struct csum_offset csum_off = {}\n",
    "        ;\n",
    "        struct ct_state ct_state_new = {}\n",
    "        ;\n",
    "        struct lb6_service *svc;\n",
    "        struct lb6_key key = {}\n",
    "        ;\n",
    "        __u16 proxy_port = 0;\n",
    "        int l4_off, hdrlen;\n",
    "        tuple.nexthdr = ip6->nexthdr;\n",
    "        ipv6_addr_copy (&tuple.daddr, (union v6addr *) &ip6->daddr);\n",
    "        ipv6_addr_copy (&tuple.saddr, (union v6addr *) &ip6->saddr);\n",
    "        hdrlen = ipv6_hdrlen (ctx, & tuple.nexthdr);\n",
    "        if (hdrlen < 0)\n",
    "            return hdrlen;\n",
    "        l4_off = ETH_HLEN + hdrlen;\n",
    "        ret = lb6_extract_key (ctx, & tuple, l4_off, & key, & csum_off, CT_EGRESS);\n",
    "        if (IS_ERR (ret)) {\n",
    "            if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)\n",
    "                goto skip_service_lookup;\n",
    "            else\n",
    "                return ret;\n",
    "        }\n",
    "        svc = lb6_lookup_service (& key, is_defined (ENABLE_NODEPORT));\n",
    "        if (svc) {\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "            if (lb6_svc_is_l7loadbalancer (svc)) {\n",
    "                proxy_port = (__u16) svc->l7_lb_proxy_port;\n",
    "                goto skip_service_lookup;\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "            ret = lb6_local (get_ct_map6 (& tuple), ctx, ETH_HLEN, l4_off, & csum_off, & key, & tuple, svc, & ct_state_new, false);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "        }\n",
    "    skip_service_lookup :\n",
    "        lb6_ctx_store_state (ctx, &ct_state_new, proxy_port);\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB */\n",
    "    invoke_tailcall_if (is_defined (ENABLE_PER_PACKET_LB), CILIUM_CALL_IPV6_CT_EGRESS, tail_ipv6_ct_egress);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int __tail_handle_ipv6(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	/* Handle special ICMPv6 messages. This includes echo requests to the
	 * logical router address, neighbour advertisements to the router.
	 * All remaining packets are subjected to forwarding into the container.
	 */
	if (unlikely(ip6->nexthdr == IPPROTO_ICMPV6)) {
		if (data + sizeof(*ip6) + ETH_HLEN + sizeof(struct icmp6hdr) > data_end)
			return DROP_INVALID;

		ret = icmp6_handle(ctx, ETH_HLEN, ip6, METRIC_EGRESS);
		if (IS_ERR(ret))
			return ret;
	}

	if (unlikely(!is_valid_lxc_src_ip(ip6)))
		return DROP_INVALID_SIP;

#ifdef ENABLE_PER_PACKET_LB
	{
		struct ipv6_ct_tuple tuple = {};
		struct csum_offset csum_off = {};
		struct ct_state ct_state_new = {};
		struct lb6_service *svc;
		struct lb6_key key = {};
		__u16 proxy_port = 0;
		int l4_off, hdrlen;

		tuple.nexthdr = ip6->nexthdr;
		ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
		ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);

		hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		l4_off = ETH_HLEN + hdrlen;

		ret = lb6_extract_key(ctx, &tuple, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}

		/*
		 * Check if the destination address is among the address that should
		 * be load balanced. This operation is performed before we go through
		 * the connection tracker to allow storing the reverse nat index in
		 * the CT entry for destination endpoints where we can't encode the
		 * state in the address.
		 */
		svc = lb6_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
#if defined(ENABLE_L7_LB)
			if (lb6_svc_is_l7loadbalancer(svc)) {
				proxy_port = (__u16)svc->l7_lb_proxy_port;
				goto skip_service_lookup;
			}
#endif /* ENABLE_L7_LB */
			ret = lb6_local(get_ct_map6(&tuple), ctx, ETH_HLEN, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					false);
			if (IS_ERR(ret))
				return ret;
		}

skip_service_lookup:
		/* Store state to be picked up on the continuation tail call. */
		lb6_ctx_store_state(ctx, &ct_state_new, proxy_port);
	}
#endif /* ENABLE_PER_PACKET_LB */

	invoke_tailcall_if(is_defined(ENABLE_PER_PACKET_LB),
			   CILIUM_CALL_IPV6_CT_EGRESS, tail_ipv6_ct_egress);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_LXC)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 697,
  "endLine": 705,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_handle_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int tail_handle_ipv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = __tail_handle_ipv6 (ctx);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, SECLABEL, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_handle_ipv6(struct __ctx_buff *ctx)
{
	int ret = __tail_handle_ipv6(ctx);

	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, SECLABEL, ret,
		    CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct ct_buffer4 {
	struct ipv4_ct_tuple tuple;
	struct ct_state ct_state;
	__u32 monitor;
	int ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct ct_buffer4);
	__uint(max_entries, 1);
} CT_TAIL_CALL_BUFFER4 __section_maps_btf;

/* Handle egress IPv6 traffic from a container after service translation has been done
 * either at the socket level or by the caller.
 * In the case of the caller doing the service translation it passes in state via CB,
 * which we take in with lb4_ctx_restore_state().
 */
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
    "map_lookup_elem": [
      {
        "opVar": "\tct_buffer ",
        "inpVar": [
          " &CT_TAIL_CALL_BUFFER4",
          " &zero"
        ]
      },
      {
        "opVar": "\t\tvtep ",
        "inpVar": [
          " &VTEP_MAP",
          " &vkey"
        ]
      }
    ],
    "redirect": [
      {
        "opVar": "\t#endif \t\tif ((ct_status ",
        "inpVar": [
          ""
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t\treturn ctx__to_proxy4ctx",
          " tuple",
          " 0",
          " false"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif !from_l7lb && _to_proxyverdict",
          " ct_status "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\treturn ctx__to_proxy4ctx",
          " tuple",
          " proxy_port",
          " false"
        ]
      },
      {
        "opVar": "\t\t\t\tret ",
        "inpVar": [
          " encap_and__lxcctx",
          " egress_gw_policy->gateway_ip",
          " encrypt_key",
          "\t\t\t\t\t     &key",
          " SECLABEL",
          " &trace"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\treturn __encap_and__with_nodeidctx",
          " vtep->tunnel_endpoint",
          "\t\t\t\t\t\t\t\tSECLABEL",
          " WORLD_ID",
          " &trace"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " encap_and__lxcctx",
          " tunnel_endpoint",
          " encrypt_key",
          "\t\t\t\t\t     &key",
          " SECLABEL",
          " &trace"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t#endif \tif is_definedENABLE_HOST_ROUTING\t\treturn _direct_v4ctx",
          " ETH_HLEN",
          " ip4"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\treturn ctx_ctx",
          " HOST_IFINDEX",
          " BPF_F_INGRESS"
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_IPV4_NODEPORT_REVNAT"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &POLICY_CALL_MAP",
          " HOST_EP_ID"
        ]
      }
    ]
  },
  "startLine": 728,
  "endLine": 1157,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_ipv4_from_lxc",
  "updateMaps": [],
  "readMaps": [
    "  VTEP_MAP",
    "  CT_TAIL_CALL_BUFFER4"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 *dst_id"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call",
    "redirect",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "static __always_inline int handle_ipv4_from_lxc (struct  __ctx_buff *ctx, __u32 *dst_id)\n",
    "{\n",
    "    struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};\n",
    "    struct ipv4_ct_tuple tuple_on_stack __maybe_unused, *tuple;\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "    union macaddr router_mac = NODE_MAC;\n",
    "\n",
    "#endif\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    int ret, verdict = 0, l4_off;\n",
    "    struct trace_ctx trace = {\n",
    "        .reason = TRACE_REASON_UNKNOWN,\n",
    "        .monitor = 0,}\n",
    "    ;\n",
    "    __u32 __maybe_unused tunnel_endpoint = 0, zero = 0;\n",
    "    __u8 __maybe_unused encrypt_key = 0;\n",
    "    bool hairpin_flow = false;\n",
    "    __u8 policy_match_type = POLICY_MATCH_NONE;\n",
    "    struct ct_buffer4 *ct_buffer;\n",
    "    __u8 audited = 0;\n",
    "    bool has_l4_header = false;\n",
    "    bool __maybe_unused dst_remote_ep = false;\n",
    "    enum ct_status ct_status;\n",
    "    __u16 proxy_port = 0;\n",
    "    bool from_l7lb = false;\n",
    "    bool emit_policy_verdict = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    has_l4_header = ipv4_has_l4_header (ip4);\n",
    "    if (1) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = lookup_ip4_remote_endpoint (ip4 -> daddr);\n",
    "        if (info && info->sec_label) {\n",
    "            *dst_id = info->sec_label;\n",
    "            tunnel_endpoint = info->tunnel_endpoint;\n",
    "            encrypt_key = get_min_encrypt_key (info -> key);\n",
    "\n",
    "#ifdef ENABLE_WIREGUARD\n",
    "            if (info->tunnel_endpoint != 0 && !identity_is_node (info->sec_label))\n",
    "                dst_remote_ep = true;\n",
    "\n",
    "#endif /* ENABLE_WIREGUARD */\n",
    "        }\n",
    "        else {\n",
    "            *dst_id = WORLD_ID;\n",
    "        }\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4, ip4->daddr, *dst_id);\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_PER_PACKET_LB\n",
    "    lb4_ctx_restore_state (ctx, &ct_state_new, ip4->daddr, &proxy_port);\n",
    "    hairpin_flow = ct_state_new.loopback;\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB */\n",
    "    l4_off = ETH_HLEN + ipv4_hdrlen (ip4);\n",
    "    ct_buffer = map_lookup_elem (& CT_TAIL_CALL_BUFFER4, & zero);\n",
    "    if (!ct_buffer)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "    if (ct_buffer->tuple.saddr == 0)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "\n",
    "#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES\n",
    "    tuple = (struct ipv4_ct_tuple *) &ct_buffer->tuple;\n",
    "    ct_state = (struct ct_state *) &ct_buffer->ct_state;\n",
    "\n",
    "#else\n",
    "    memcpy (&tuple_on_stack, &ct_buffer->tuple, sizeof (tuple_on_stack));\n",
    "    tuple = &tuple_on_stack;\n",
    "    memcpy (&ct_state_on_stack, &ct_buffer->ct_state, sizeof (ct_state_on_stack));\n",
    "    ct_state = &ct_state_on_stack;\n",
    "\n",
    "#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */\n",
    "    trace.monitor = ct_buffer->monitor;\n",
    "    ret = ct_buffer->ret;\n",
    "    ct_status = (enum ct_status) ret;\n",
    "    trace.reason = (enum trace_reason) ret;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    if (proxy_port > 0) {\n",
    "        cilium_dbg3 (ctx, DBG_L7_LB, tuple->daddr, tuple->saddr, bpf_ntohs (proxy_port));\n",
    "        verdict = proxy_port;\n",
    "        emit_policy_verdict = false;\n",
    "        goto skip_policy_enforcement;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "    if ((ct_status == CT_REPLY || ct_status == CT_RELATED) && ct_state->proxy_redirect) {\n",
    "        return ctx_redirect_to_proxy4 (ctx, tuple, 0, false);\n",
    "    }\n",
    "    if (hairpin_flow) {\n",
    "        emit_policy_verdict = false;\n",
    "        goto skip_policy_enforcement;\n",
    "    }\n",
    "    verdict = policy_can_egress4 (ctx, tuple, SECLABEL, * dst_id, & policy_match_type, & audited);\n",
    "    if (ct_status != CT_REPLY && ct_status != CT_RELATED && verdict < 0) {\n",
    "        send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 0, verdict, policy_match_type, audited);\n",
    "        return verdict;\n",
    "    }\n",
    "skip_policy_enforcement :\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    from_l7lb = ctx_load_meta (ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;\n",
    "\n",
    "#endif\n",
    "    switch (ct_status) {\n",
    "    case CT_NEW :\n",
    "        if (emit_policy_verdict)\n",
    "            send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 0, verdict, policy_match_type, audited);\n",
    "    ct_recreate4 :\n",
    "        ct_state_new.src_sec_id = SECLABEL;\n",
    "        ret = ct_create4 (get_ct_map4 (tuple), & CT_MAP_ANY4, tuple, ctx, CT_EGRESS, & ct_state_new, verdict > 0, from_l7lb);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        break;\n",
    "    case CT_REOPENED :\n",
    "        if (emit_policy_verdict)\n",
    "            send_policy_verdict_notify (ctx, *dst_id, tuple->dport, tuple->nexthdr, POLICY_EGRESS, 0, verdict, policy_match_type, audited);\n",
    "    case CT_ESTABLISHED :\n",
    "        if (unlikely (ct_state->rev_nat_index != ct_state_new.rev_nat_index))\n",
    "            goto ct_recreate4;\n",
    "        break;\n",
    "    case CT_RELATED :\n",
    "    case CT_REPLY :\n",
    "        policy_mark_skip (ctx);\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "\n",
    "# ifdef ENABLE_DSR\n",
    "        if (ct_state->dsr) {\n",
    "            ret = xlate_dsr_v4 (ctx, tuple, l4_off, has_l4_header);\n",
    "            if (ret != 0)\n",
    "                return ret;\n",
    "        }\n",
    "        else\n",
    "\n",
    "# endif /* ENABLE_DSR */\n",
    "            if (ct_state->node_port) {\n",
    "                send_trace_notify (ctx, TRACE_TO_NETWORK, SECLABEL, *dst_id, 0, 0, trace.reason, trace.monitor);\n",
    "                ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;\n",
    "                ep_tail_call (ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);\n",
    "                return DROP_MISSED_TAIL_CALL;\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "        if (ct_state->rev_nat_index) {\n",
    "            struct csum_offset csum_off = {}\n",
    "            ;\n",
    "            csum_l4_offset_and_flags (tuple->nexthdr, &csum_off);\n",
    "            ret = lb4_rev_nat (ctx, ETH_HLEN, l4_off, & csum_off, ct_state, tuple, 0, has_l4_header);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_CT;\n",
    "    }\n",
    "    hairpin_flow |= ct_state->loopback;\n",
    "    if (!from_l7lb && redirect_to_proxy (verdict, ct_status)) {\n",
    "        proxy_port = (__u16) verdict;\n",
    "        send_trace_notify (ctx, TRACE_TO_PROXY, SECLABEL, 0, bpf_ntohs (proxy_port), 0, trace.reason, trace.monitor);\n",
    "        return ctx_redirect_to_proxy4 (ctx, tuple, proxy_port, false);\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    if (is_defined (ENABLE_ROUTING) || hairpin_flow) {\n",
    "        struct endpoint_info *ep;\n",
    "        ep = lookup_ip4_endpoint (ip4);\n",
    "        if (ep) {\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "            if (ep->flags & ENDPOINT_F_HOST) {\n",
    "\n",
    "#ifdef HOST_IFINDEX\n",
    "                goto to_host;\n",
    "\n",
    "#else\n",
    "                return DROP_HOST_UNREACHABLE;\n",
    "\n",
    "#endif\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_ROUTING */\n",
    "            policy_clear_mark (ctx);\n",
    "            return ipv4_local_delivery (ctx, ETH_HLEN, SECLABEL, ip4, ep, METRIC_EGRESS, from_l7lb);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)\n",
    "    if (*dst_id == HOST_ID) {\n",
    "        ctx_store_meta (ctx, CB_FROM_HOST, 0);\n",
    "        tail_call_static (ctx, &POLICY_CALL_MAP, HOST_EP_ID);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */\n",
    "\n",
    "#ifdef ENABLE_EGRESS_GATEWAY\n",
    "    {\n",
    "        struct egress_gw_policy_entry *egress_gw_policy;\n",
    "        struct endpoint_info *gateway_node_ep;\n",
    "        struct endpoint_key key = {}\n",
    "        ;\n",
    "        if (identity_is_cluster (*dst_id))\n",
    "            goto skip_egress_gateway;\n",
    "        if (ct_status == CT_REPLY || ct_status == CT_RELATED)\n",
    "            goto skip_egress_gateway;\n",
    "        egress_gw_policy = lookup_ip4_egress_gw_policy (ip4 -> saddr, ip4 -> daddr);\n",
    "        if (!egress_gw_policy)\n",
    "            goto skip_egress_gateway;\n",
    "        gateway_node_ep = __lookup_ip4_endpoint (egress_gw_policy -> gateway_ip);\n",
    "        if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))\n",
    "            goto skip_egress_gateway;\n",
    "        ret = encap_and_redirect_lxc (ctx, egress_gw_policy -> gateway_ip, encrypt_key, & key, SECLABEL, & trace);\n",
    "        if (ret == IPSEC_ENDPOINT)\n",
    "            goto encrypt_to_stack;\n",
    "        else\n",
    "            return ret;\n",
    "    }\n",
    "skip_egress_gateway :\n",
    "\n",
    "#endif\n",
    "\n",
    "#if defined(ENABLE_VTEP)\n",
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
    "            return __encap_and_redirect_with_nodeid (ctx, vtep->tunnel_endpoint, SECLABEL, WORLD_ID, &trace);\n",
    "        }\n",
    "    }\n",
    "skip_vtep :\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef TUNNEL_MODE\n",
    "\n",
    "# ifdef ENABLE_WIREGUARD\n",
    "    if (!dst_remote_ep)\n",
    "\n",
    "# endif /* ENABLE_WIREGUARD */\n",
    "        {\n",
    "            struct endpoint_key key = {}\n",
    "            ;\n",
    "            key.ip4 = ip4->daddr & IPV4_MASK;\n",
    "            key.family = ENDPOINT_KEY_IPV4;\n",
    "            ret = encap_and_redirect_lxc (ctx, tunnel_endpoint, encrypt_key, & key, SECLABEL, & trace);\n",
    "            if (ret == DROP_NO_TUNNEL_ENDPOINT)\n",
    "                goto pass_to_stack;\n",
    "            else if (ret == IPSEC_ENDPOINT)\n",
    "                goto encrypt_to_stack;\n",
    "            else\n",
    "                return ret;\n",
    "        }\n",
    "\n",
    "#endif /* TUNNEL_MODE */\n",
    "    if (is_defined (ENABLE_HOST_ROUTING))\n",
    "        return redirect_direct_v4 (ctx, ETH_HLEN, ip4);\n",
    "    goto pass_to_stack;\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "to_host :\n",
    "    if (is_defined (ENABLE_HOST_FIREWALL) && *dst_id == HOST_ID) {\n",
    "        send_trace_notify (ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0, HOST_IFINDEX, trace.reason, trace.monitor);\n",
    "        return ctx_redirect (ctx, HOST_IFINDEX, BPF_F_INGRESS);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "pass_to_stack :\n",
    "\n",
    "#ifdef ENABLE_ROUTING\n",
    "    ret = ipv4_l3 (ctx, ETH_HLEN, NULL, (__u8 *) & router_mac.addr, ip4);\n",
    "    if (unlikely (ret != CTX_ACT_OK))\n",
    "        return ret;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_WIREGUARD\n",
    "    if (dst_remote_ep)\n",
    "        set_encrypt_mark (ctx);\n",
    "    else\n",
    "\n",
    "#elif !defined(TUNNEL_MODE)\n",
    "\n",
    "# ifdef ENABLE_IPSEC\n",
    "        if (encrypt_key && tunnel_endpoint) {\n",
    "            set_encrypt_key_mark (ctx, encrypt_key);\n",
    "\n",
    "#  ifdef IP_POOLS\n",
    "            set_encrypt_dip (ctx, tunnel_endpoint);\n",
    "\n",
    "#  endif /* IP_POOLS */\n",
    "\n",
    "#  ifdef ENABLE_IDENTITY_MARK\n",
    "            set_identity_mark (ctx, SECLABEL);\n",
    "\n",
    "#  endif\n",
    "        }\n",
    "        else\n",
    "\n",
    "# endif /* ENABLE_IPSEC */\n",
    "\n",
    "#endif /* ENABLE_WIREGUARD */\n",
    "            {\n",
    "\n",
    "#ifdef ENABLE_IDENTITY_MARK\n",
    "                ctx->mark |= MARK_MAGIC_IDENTITY;\n",
    "                set_identity_mark (ctx, SECLABEL);\n",
    "\n",
    "#endif\n",
    "            }\n",
    "\n",
    "#if defined(TUNNEL_MODE) || defined(ENABLE_EGRESS_GATEWAY)\n",
    "encrypt_to_stack :\n",
    "\n",
    "#endif\n",
    "    send_trace_notify (ctx, TRACE_TO_STACK, SECLABEL, *dst_id, 0, 0, trace.reason, trace.monitor);\n",
    "    cilium_dbg_capture (ctx, DBG_CAPTURE_DELIVERY, 0);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int handle_ipv4_from_lxc(struct __ctx_buff *ctx, __u32 *dst_id)
{
	struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};
	struct ipv4_ct_tuple tuple_on_stack __maybe_unused, *tuple;
#ifdef ENABLE_ROUTING
	union macaddr router_mac = NODE_MAC;
#endif
	void *data, *data_end;
	struct iphdr *ip4;
	int ret, verdict = 0, l4_off;
	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};
	__u32 __maybe_unused tunnel_endpoint = 0, zero = 0;
	__u8 __maybe_unused encrypt_key = 0;
	bool hairpin_flow = false; /* endpoint wants to access itself via service IP */
	__u8 policy_match_type = POLICY_MATCH_NONE;
	struct ct_buffer4 *ct_buffer;
	__u8 audited = 0;
	bool has_l4_header = false;
	bool __maybe_unused dst_remote_ep = false;
	enum ct_status ct_status;
	__u16 proxy_port = 0;
	bool from_l7lb = false;
	bool emit_policy_verdict = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	has_l4_header = ipv4_has_l4_header(ip4);

	/* Determine the destination category for policy fallback. */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->daddr);
		if (info && info->sec_label) {
			*dst_id = info->sec_label;
			tunnel_endpoint = info->tunnel_endpoint;
			encrypt_key = get_min_encrypt_key(info->key);
#ifdef ENABLE_WIREGUARD
			/* If we detect that the dst is a remote endpoint, we
			 * need to mark the packet. The ip rule which matches
			 * on the MARK_MAGIC_ENCRYPT mark will steer the packet
			 * to the Wireguard tunnel. The marking happens lower
			 * in the code in the same place where we handle IPSec.
			 */
			if (info->tunnel_endpoint != 0 &&
			    !identity_is_node(info->sec_label))
				dst_remote_ep = true;
#endif /* ENABLE_WIREGUARD */
		} else {
			*dst_id = WORLD_ID;
		}

		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->daddr, *dst_id);
	}

#ifdef ENABLE_PER_PACKET_LB
	/* Restore ct_state from per packet lb handling in the previous tail call. */
	lb4_ctx_restore_state(ctx, &ct_state_new, ip4->daddr, &proxy_port);
	hairpin_flow = ct_state_new.loopback;
#endif /* ENABLE_PER_PACKET_LB */

	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES
	tuple = (struct ipv4_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
#else
	memcpy(&tuple_on_stack, &ct_buffer->tuple, sizeof(tuple_on_stack));
	tuple = &tuple_on_stack;
	memcpy(&ct_state_on_stack, &ct_buffer->ct_state, sizeof(ct_state_on_stack));
	ct_state = &ct_state_on_stack;
#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */
	trace.monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	ct_status = (enum ct_status)ret;
	trace.reason = (enum trace_reason)ret;

#if defined(ENABLE_L7_LB)
	if (proxy_port > 0) {
		/* tuple addresses have been swapped by CT lookup */
		cilium_dbg3(ctx, DBG_L7_LB, tuple->daddr, tuple->saddr, bpf_ntohs(proxy_port));
		verdict = proxy_port;
		emit_policy_verdict = false;
		goto skip_policy_enforcement;
	}
#endif /* ENABLE_L7_LB */

	/* Check it this is return traffic to an ingress proxy. */
	if ((ct_status == CT_REPLY || ct_status == CT_RELATED) && ct_state->proxy_redirect) {
		/* Stack will do a socket match and deliver locally. */
		return ctx_redirect_to_proxy4(ctx, tuple, 0, false);
	}

	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (hairpin_flow) {
		emit_policy_verdict = false;
		goto skip_policy_enforcement;
	}

	/* If the packet is in the establishing direction and it's destined
	 * within the cluster, it must match policy or be dropped. If it's
	 * bound for the host/outside, perform the CIDR policy check.
	 */
	verdict = policy_can_egress4(ctx, tuple, SECLABEL, *dst_id,
				     &policy_match_type, &audited);

	if (ct_status != CT_REPLY && ct_status != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
					   tuple->nexthdr, POLICY_EGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

skip_policy_enforcement:
#if defined(ENABLE_L7_LB)
	from_l7lb = ctx_load_meta(ctx, CB_FROM_HOST) == FROM_HOST_L7_LB;
#endif
	switch (ct_status) {
	case CT_NEW:
		if (emit_policy_verdict)
			send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 0,
						   verdict, policy_match_type, audited);
ct_recreate4:
		/* New connection implies that rev_nat_index remains untouched
		 * to the index provided by the loadbalancer (if it applied).
		 * Create a CT entry which allows to track replies and to
		 * reverse NAT.
		 */
		ct_state_new.src_sec_id = SECLABEL;
		/* We could avoid creating related entries for legacy ClusterIP
		 * handling here, but turns out that verifier cannot handle it.
		 */
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple, ctx,
				 CT_EGRESS, &ct_state_new, verdict > 0, from_l7lb);
		if (IS_ERR(ret))
			return ret;
		break;

	case CT_REOPENED:
		if (emit_policy_verdict)
			send_policy_verdict_notify(ctx, *dst_id, tuple->dport,
						   tuple->nexthdr, POLICY_EGRESS, 0,
						   verdict, policy_match_type, audited);
	case CT_ESTABLISHED:
		/* Did we end up at a stale non-service entry? Recreate if so. */
		if (unlikely(ct_state->rev_nat_index != ct_state_new.rev_nat_index))
			goto ct_recreate4;
		break;

	case CT_RELATED:
	case CT_REPLY:
		policy_mark_skip(ctx);

#ifdef ENABLE_NODEPORT
# ifdef ENABLE_DSR
		if (ct_state->dsr) {
			ret = xlate_dsr_v4(ctx, tuple, l4_off, has_l4_header);
			if (ret != 0)
				return ret;
		} else
# endif /* ENABLE_DSR */
		/* This handles reply traffic for the case where the nodeport EP
		 * is local to the node. We'll do the tail call to perform
		 * the reverse DNAT.
		 */
		if (ct_state->node_port) {
			send_trace_notify(ctx, TRACE_TO_NETWORK, SECLABEL,
					  *dst_id, 0, 0,
					  trace.reason, trace.monitor);
			ctx->tc_index |= TC_INDEX_F_SKIP_RECIRCULATION;
			ep_tail_call(ctx, CILIUM_CALL_IPV4_NODEPORT_REVNAT);
			return DROP_MISSED_TAIL_CALL;
		}

#endif /* ENABLE_NODEPORT */

		if (ct_state->rev_nat_index) {
			struct csum_offset csum_off = {};

			csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);
			ret = lb4_rev_nat(ctx, ETH_HLEN, l4_off, &csum_off,
					  ct_state, tuple, 0, has_l4_header);
			if (IS_ERR(ret))
				return ret;
		}
		break;

	default:
		return DROP_UNKNOWN_CT;
	}

	hairpin_flow |= ct_state->loopback;

	/* L7 LB does L7 policy enforcement, so we only redirect packets
	 * NOT from L7 LB.
	 */
	if (!from_l7lb && redirect_to_proxy(verdict, ct_status)) {
		proxy_port = (__u16)verdict;
		/* Trace the packet before it is forwarded to proxy */
		send_trace_notify(ctx, TRACE_TO_PROXY, SECLABEL, 0,
				  bpf_ntohs(proxy_port), 0,
				  trace.reason, trace.monitor);
		return ctx_redirect_to_proxy4(ctx, tuple, proxy_port, false);
	}

	/* After L4 write in port mapping: revalidate for direct packet access */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	/* Allow a hairpin packet to be redirected even if ENABLE_ROUTING is
	 * disabled. Otherwise, the packet will be dropped by the kernel if
	 * it is going to be routed via an interface it came from after it has
	 * been passed to the stack.
	 */
	if (is_defined(ENABLE_ROUTING) || hairpin_flow) {
		struct endpoint_info *ep;

		/* Lookup IPv4 address, this will return a match if:
		 *  - The destination IP address belongs to a local endpoint
		 *    managed by cilium
		 *  - The destination IP address is an IP address associated with the
		 *    host itself
		 *  - The destination IP address belongs to endpoint itself.
		 */
		ep = lookup_ip4_endpoint(ip4);
		if (ep) {
#ifdef ENABLE_ROUTING
			if (ep->flags & ENDPOINT_F_HOST) {
#ifdef HOST_IFINDEX
				goto to_host;
#else
				return DROP_HOST_UNREACHABLE;
#endif
			}
#endif /* ENABLE_ROUTING */
			policy_clear_mark(ctx);
			/* If the packet is from L7 LB it is coming from the host */
			return ipv4_local_delivery(ctx, ETH_HLEN, SECLABEL, ip4,
						   ep, METRIC_EGRESS, from_l7lb);
		}
	}

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the destination is the local host and per-endpoint routes are
	 * enabled, jump to the bpf_host program to enforce ingress host policies.
	 */
	if (*dst_id == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 0);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

#ifdef ENABLE_EGRESS_GATEWAY
	{
		struct egress_gw_policy_entry *egress_gw_policy;
		struct endpoint_info *gateway_node_ep;
		struct endpoint_key key = {};

		/* If the packet is destined to an entity inside the cluster,
		 * either EP or node, it should not be forwarded to an egress
		 * gateway since only traffic leaving the cluster is supposed to
		 * be masqueraded with an egress IP.
		 */
		if (identity_is_cluster(*dst_id))
			goto skip_egress_gateway;

		/* If the packet is a reply or is related, it means that outside
		 * has initiated the connection, and so we should skip egress
		 * gateway, since an egress policy is only matching connections
		 * originating from a pod.
		 */
		if (ct_status == CT_REPLY || ct_status == CT_RELATED)
			goto skip_egress_gateway;

		egress_gw_policy = lookup_ip4_egress_gw_policy(ip4->saddr, ip4->daddr);
		if (!egress_gw_policy)
			goto skip_egress_gateway;

		/* If the gateway node is the local node, then just let the
		 * packet go through, as it will be SNATed later on by
		 * handle_nat_fwd().
		 */
		gateway_node_ep = __lookup_ip4_endpoint(egress_gw_policy->gateway_ip);
		if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
			goto skip_egress_gateway;

		/* Otherwise encap and redirect the packet to egress gateway
		 * node through a tunnel.
		 */
		ret = encap_and_redirect_lxc(ctx, egress_gw_policy->gateway_ip, encrypt_key,
					     &key, SECLABEL, &trace);
		if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		else
			return ret;
	}
skip_egress_gateway:
#endif

	/* L7 proxy result in VTEP redirection in bpf_host, but when L7 proxy disabled
	 * We want VTEP redirection handled earlier here to avoid packets passing to
	 * stack to bpf_host for VTEP redirection. When L7 proxy enabled, but no
	 * L7 policy applied to pod, VTEP redirection also happen here.
	 */
#if defined(ENABLE_VTEP)
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
								SECLABEL, WORLD_ID, &trace);
		}
	}
skip_vtep:
#endif

#ifdef TUNNEL_MODE
# ifdef ENABLE_WIREGUARD
	/* In the tunnel mode we encapsulate pod2pod traffic only via Wireguard
	 * device, i.e. we do not encapsulate twice.
	 */
	if (!dst_remote_ep)
# endif /* ENABLE_WIREGUARD */
	{
		struct endpoint_key key = {};

		key.ip4 = ip4->daddr & IPV4_MASK;
		key.family = ENDPOINT_KEY_IPV4;

		ret = encap_and_redirect_lxc(ctx, tunnel_endpoint, encrypt_key,
					     &key, SECLABEL, &trace);
		if (ret == DROP_NO_TUNNEL_ENDPOINT)
			goto pass_to_stack;
		/* If not redirected noteably due to IPSEC then pass up to stack
		 * for further processing.
		 */
		else if (ret == IPSEC_ENDPOINT)
			goto encrypt_to_stack;
		/* This is either redirect by encap code or an error has
		 * occurred either way return and stack will consume ctx.
		 */
		else
			return ret;
	}
#endif /* TUNNEL_MODE */
	if (is_defined(ENABLE_HOST_ROUTING))
		return redirect_direct_v4(ctx, ETH_HLEN, ip4);

	goto pass_to_stack;

#ifdef ENABLE_ROUTING
to_host:
	if (is_defined(ENABLE_HOST_FIREWALL) && *dst_id == HOST_ID) {
		send_trace_notify(ctx, TRACE_TO_HOST, SECLABEL, HOST_ID, 0,
				  HOST_IFINDEX, trace.reason, trace.monitor);
		return ctx_redirect(ctx, HOST_IFINDEX, BPF_F_INGRESS);
	}
#endif

pass_to_stack:
#ifdef ENABLE_ROUTING
	ret = ipv4_l3(ctx, ETH_HLEN, NULL, (__u8 *)&router_mac.addr, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
#endif

#ifdef ENABLE_WIREGUARD
	if (dst_remote_ep)
		set_encrypt_mark(ctx);
	else /* Wireguard and identity mark are mutually exclusive */
#elif !defined(TUNNEL_MODE)
# ifdef ENABLE_IPSEC
	if (encrypt_key && tunnel_endpoint) {
		set_encrypt_key_mark(ctx, encrypt_key);
#  ifdef IP_POOLS
		set_encrypt_dip(ctx, tunnel_endpoint);
#  endif /* IP_POOLS */
#  ifdef ENABLE_IDENTITY_MARK
		set_identity_mark(ctx, SECLABEL);
#  endif
	} else
# endif /* ENABLE_IPSEC */
#endif /* ENABLE_WIREGUARD */
	{
#ifdef ENABLE_IDENTITY_MARK
		/* Always encode the source identity when passing to the stack.
		 * If the stack hairpins the packet back to a local endpoint the
		 * source identity can still be derived even if SNAT is
		 * performed by a component such as portmap.
		 */
		ctx->mark |= MARK_MAGIC_IDENTITY;
		set_identity_mark(ctx, SECLABEL);
#endif
	}

#if defined(TUNNEL_MODE) || defined(ENABLE_EGRESS_GATEWAY)
encrypt_to_stack:
#endif
	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, *dst_id, 0, 0,
			  trace.reason, trace.monitor);
	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, 0);
	return CTX_ACT_OK;
}

declare_tailcall_if(is_defined(ENABLE_PER_PACKET_LB), CILIUM_CALL_IPV4_FROM_LXC_CONT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV4_EGRESS"
        ]
      }
    ]
  },
  "startLine": 1160,
  "endLine": 1179,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_handle_ipv4_cont",
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
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int tail_handle_ipv4_cont (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 dst_id = 0;\n",
    "    int ret = handle_ipv4_from_lxc (ctx, & dst_id);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, SECLABEL, dst_id, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!encode_custom_prog_meta (ctx, ret, dst_id)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV4_EGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_EGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_handle_ipv4_cont(struct __ctx_buff *ctx)
{
	__u32 dst_id = 0;
	int ret = handle_ipv4_from_lxc(ctx, &dst_id);

	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, dst_id, 0, ret,
					CTX_ACT_DROP, METRIC_EGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	if (!encode_custom_prog_meta(ctx, ret, dst_id)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_EGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_EGRESS, tail_ipv4_ct_egress, CT_EGRESS,
		is_defined(ENABLE_PER_PACKET_LB),
		CILIUM_CALL_IPV4_FROM_LXC_CONT, tail_handle_ipv4_cont)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1185,
  "endLine": 1256,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "__tail_handle_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline int __tail_handle_ipv4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    int ret;\n",
    "    if (!revalidate_data_pull (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "\n",
    "#ifndef ENABLE_IPV4_FRAGMENTS\n",
    "    if (ipv4_is_fragment (ip4))\n",
    "        return DROP_FRAG_NOSUPPORT;\n",
    "\n",
    "#endif\n",
    "    if (unlikely (!is_valid_lxc_src_ipv4 (ip4)))\n",
    "        return DROP_INVALID_SIP;\n",
    "\n",
    "#ifdef ENABLE_PER_PACKET_LB\n",
    "    {\n",
    "        struct ipv4_ct_tuple tuple = {}\n",
    "        ;\n",
    "        struct csum_offset csum_off = {}\n",
    "        ;\n",
    "        struct ct_state ct_state_new = {}\n",
    "        ;\n",
    "        bool has_l4_header;\n",
    "        struct lb4_service *svc;\n",
    "        struct lb4_key key = {}\n",
    "        ;\n",
    "        __u16 proxy_port = 0;\n",
    "        int l4_off;\n",
    "        has_l4_header = ipv4_has_l4_header (ip4);\n",
    "        tuple.nexthdr = ip4->protocol;\n",
    "        tuple.daddr = ip4->daddr;\n",
    "        tuple.saddr = ip4->saddr;\n",
    "        l4_off = ETH_HLEN + ipv4_hdrlen (ip4);\n",
    "        ret = lb4_extract_key (ctx, ip4, l4_off, & key, & csum_off, CT_EGRESS);\n",
    "        if (IS_ERR (ret)) {\n",
    "            if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)\n",
    "                goto skip_service_lookup;\n",
    "            else\n",
    "                return ret;\n",
    "        }\n",
    "        svc = lb4_lookup_service (& key, is_defined (ENABLE_NODEPORT));\n",
    "        if (svc) {\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "            if (lb4_svc_is_l7loadbalancer (svc)) {\n",
    "                proxy_port = (__u16) svc->l7_lb_proxy_port;\n",
    "                goto skip_service_lookup;\n",
    "            }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "            ret = lb4_local (get_ct_map4 (& tuple), ctx, ETH_HLEN, l4_off, & csum_off, & key, & tuple, svc, & ct_state_new, ip4 -> saddr, has_l4_header, false);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "        }\n",
    "    skip_service_lookup :\n",
    "        lb4_ctx_store_state (ctx, &ct_state_new, proxy_port);\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB */\n",
    "    invoke_tailcall_if (is_defined (ENABLE_PER_PACKET_LB), CILIUM_CALL_IPV4_CT_EGRESS, tail_ipv4_ct_egress);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int __tail_handle_ipv4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

/* If IPv4 fragmentation is disabled
 * AND a IPv4 fragmented packet is received,
 * then drop the packet.
 */
#ifndef ENABLE_IPV4_FRAGMENTS
	if (ipv4_is_fragment(ip4))
		return DROP_FRAG_NOSUPPORT;
#endif

	if (unlikely(!is_valid_lxc_src_ipv4(ip4)))
		return DROP_INVALID_SIP;

#ifdef ENABLE_PER_PACKET_LB
	{
		struct ipv4_ct_tuple tuple = {};
		struct csum_offset csum_off = {};
		struct ct_state ct_state_new = {};
		bool has_l4_header;
		struct lb4_service *svc;
		struct lb4_key key = {};
		__u16 proxy_port = 0;
		int l4_off;

		has_l4_header = ipv4_has_l4_header(ip4);
		tuple.nexthdr = ip4->protocol;
		tuple.daddr = ip4->daddr;
		tuple.saddr = ip4->saddr;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

		ret = lb4_extract_key(ctx, ip4, l4_off, &key, &csum_off,
				      CT_EGRESS);
		if (IS_ERR(ret)) {
			if (ret == DROP_NO_SERVICE || ret == DROP_UNKNOWN_L4)
				goto skip_service_lookup;
			else
				return ret;
		}

		svc = lb4_lookup_service(&key, is_defined(ENABLE_NODEPORT));
		if (svc) {
#if defined(ENABLE_L7_LB)
			if (lb4_svc_is_l7loadbalancer(svc)) {
				proxy_port = (__u16)svc->l7_lb_proxy_port;
				goto skip_service_lookup;
			}
#endif /* ENABLE_L7_LB */
			ret = lb4_local(get_ct_map4(&tuple), ctx, ETH_HLEN, l4_off,
					&csum_off, &key, &tuple, svc, &ct_state_new,
					ip4->saddr, has_l4_header, false);
			if (IS_ERR(ret))
				return ret;
		}
skip_service_lookup:
		/* Store state to be picked up on the continuation tail call. */
		lb4_ctx_store_state(ctx, &ct_state_new, proxy_port);
	}
#endif /* ENABLE_PER_PACKET_LB */

	invoke_tailcall_if(is_defined(ENABLE_PER_PACKET_LB),
			   CILIUM_CALL_IPV4_CT_EGRESS, tail_ipv4_ct_egress);
	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_LXC)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1259,
  "endLine": 1267,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_handle_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int tail_handle_ipv4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = __tail_handle_ipv4 (ctx);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, SECLABEL, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_handle_ipv4(struct __ctx_buff *ctx)
{
	int ret = __tail_handle_ipv4(ctx);

	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, SECLABEL, ret,
		    CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_ARP_RESPONDER
/*
 * ARP responder for ARP requests from container
 * Respond to IPV4_GATEWAY with NODE_MAC
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_ARP)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1275,
  "endLine": 1300,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_handle_arp",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int tail_handle_arp (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    union macaddr mac = NODE_MAC;\n",
    "    union macaddr smac;\n",
    "    __be32 sip;\n",
    "    __be32 tip;\n",
    "    if (!arp_validate (ctx, &mac, &smac, &sip, &tip))\n",
    "        return CTX_ACT_OK;\n",
    "    if (tip == LXC_IPV4)\n",
    "        return CTX_ACT_OK;\n",
    "    return arp_respond (ctx, &mac, tip, &smac, sip, 0);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_handle_arp(struct __ctx_buff *ctx)
{
	union macaddr mac = NODE_MAC;
	union macaddr smac;
	__be32 sip;
	__be32 tip;

	/* Pass any unknown ARP requests to the Linux stack */
	if (!arp_validate(ctx, &mac, &smac, &sip, &tip))
		return CTX_ACT_OK;

	/*
	 * The endpoint is expected to make ARP requests for its gateway IP.
	 * Most of the time, the gateway IP configured on the endpoint is
	 * IPV4_GATEWAY but it may not be the case if after cilium agent reload
	 * a different gateway is chosen. In such a case, existing endpoints
	 * will have an old gateway configured. Since we don't know the IP of
	 * previous gateways, we answer requests for all IPs with the exception
	 * of the LXC IP (to avoid specific problems, like IP duplicate address
	 * detection checks that might run within the container).
	 */
	if (tip == LXC_IPV4)
		return CTX_ACT_OK;

	return arp_respond(ctx, &mac, tip, &smac, sip, 0);
}
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */

/* Attachment/entry point is ingress for veth, egress for ipvlan.
 * It corresponds to packets leaving the container.
 */
__section("from-container")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_LXC"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tep_ctx",
          " CILIUM_CALL_IPV4_FROM_LXC"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#elif definedENABLE_ARP_RESPONDER\tcase bpf_htonsETH_P_ARP:\t\tep_ctx",
          " CILIUM_CALL_ARP"
        ]
      }
    ]
  },
  "startLine": 1308,
  "endLine": 1358,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_xgress",
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
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int handle_xgress (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u16 proto;\n",
    "    int ret;\n",
    "    bpf_clear_meta (ctx);\n",
    "    reset_queue_mapping (ctx);\n",
    "    send_trace_notify (ctx, TRACE_FROM_LXC, SECLABEL, 0, 0, 0, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        edt_set_aggregate (ctx, LXC_ID);\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_LXC);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        edt_set_aggregate (ctx, LXC_ID);\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_LXC);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#ifdef ENABLE_ARP_PASSTHROUGH\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "#elif defined(ENABLE_ARP_RESPONDER)\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ep_tail_call (ctx, CILIUM_CALL_ARP);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_ARP_RESPONDER */\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int handle_xgress(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;

	bpf_clear_meta(ctx);
	reset_queue_mapping(ctx);

	send_trace_notify(ctx, TRACE_FROM_LXC, SECLABEL, 0, 0, 0,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		edt_set_aggregate(ctx, LXC_ID);
		ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_LXC);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		edt_set_aggregate(ctx, LXC_ID);
		ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#ifdef ENABLE_ARP_PASSTHROUGH
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#elif defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ep_tail_call(ctx, CILIUM_CALL_ARP);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_ARP_RESPONDER */
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, 0, 0, ret, CTX_ACT_DROP,
					METRIC_EGRESS);
	return ret;
}

#ifdef ENABLE_IPV6
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
    "map_lookup_elem": [
      {
        "opVar": "\tct_buffer ",
        "inpVar": [
          " &CT_TAIL_CALL_BUFFER6",
          " &zero"
        ]
      }
    ],
    "redirect": [
      {
        "opVar": "\t\tif ((ret ",
        "inpVar": [
          ""
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\tif _to_proxyverdict",
          " *ct_status "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\tif ifindex\t\treturn _epctx",
          " ifindex",
          " from_host"
        ]
      }
    ]
  },
  "startLine": 1361,
  "endLine": 1536,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "ipv6_policy",
  "updateMaps": [],
  "readMaps": [
    "  CT_TAIL_CALL_BUFFER6"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int ifindex",
    " __u32 src_label",
    " enum ct_status *ct_status",
    " struct ipv6_ct_tuple *tuple_out",
    " __u16 *proxy_port",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "static __always_inline int ipv6_policy (struct  __ctx_buff *ctx, int ifindex, __u32 src_label, enum ct_status *ct_status, struct ipv6_ct_tuple *tuple_out, __u16 *proxy_port, bool from_host __maybe_unused)\n",
    "{\n",
    "    struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};\n",
    "    struct ipv6_ct_tuple tuple_on_stack __maybe_unused, *tuple;\n",
    "    int ret, verdict, hdrlen, zero = 0;\n",
    "    struct ct_buffer6 *ct_buffer;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    bool skip_ingress_proxy = false;\n",
    "    enum trace_reason reason;\n",
    "    union v6addr orig_sip;\n",
    "    __u32 monitor = 0;\n",
    "    __u8 policy_match_type = POLICY_MATCH_NONE;\n",
    "    __u8 audited = 0;\n",
    "    bool emit_policy_verdict = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    policy_clear_mark (ctx);\n",
    "    ipv6_addr_copy (&orig_sip, (union v6addr *) &ip6->saddr);\n",
    "    skip_ingress_proxy = tc_index_skip_ingress_proxy (ctx);\n",
    "    ct_buffer = map_lookup_elem (& CT_TAIL_CALL_BUFFER6, & zero);\n",
    "    if (!ct_buffer)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "    if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "\n",
    "#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES\n",
    "    tuple = (struct ipv6_ct_tuple *) &ct_buffer->tuple;\n",
    "    ct_state = (struct ct_state *) &ct_buffer->ct_state;\n",
    "\n",
    "#else\n",
    "    memcpy (&tuple_on_stack, &ct_buffer->tuple, sizeof (tuple_on_stack));\n",
    "    tuple = &tuple_on_stack;\n",
    "    memcpy (&ct_state_on_stack, &ct_buffer->ct_state, sizeof (ct_state_on_stack));\n",
    "    ct_state = &ct_state_on_stack;\n",
    "\n",
    "#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */\n",
    "    monitor = ct_buffer->monitor;\n",
    "    ret = ct_buffer->ret;\n",
    "    *ct_status = (enum ct_status) ret;\n",
    "    if ((ret == CT_REPLY || ret == CT_RELATED) && (ct_state_is_from_l7lb (ct_state) || (ct_state->proxy_redirect && !tc_index_skip_egress_proxy (ctx)))) {\n",
    "        send_trace_notify6 (ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip, 0, ifindex, (enum trace_reason) ret, monitor);\n",
    "        if (tuple_out)\n",
    "            memcpy (tuple_out, tuple, sizeof (*tuple));\n",
    "        return POLICY_ACT_PROXY_REDIRECT;\n",
    "    }\n",
    "    if (unlikely (ct_state->rev_nat_index)) {\n",
    "        struct csum_offset csum_off = {}\n",
    "        ;\n",
    "        int ret2, l4_off;\n",
    "        hdrlen = ipv6_hdrlen (ctx, & tuple -> nexthdr);\n",
    "        if (hdrlen < 0)\n",
    "            return hdrlen;\n",
    "        l4_off = ETH_HLEN + hdrlen;\n",
    "        csum_l4_offset_and_flags (tuple->nexthdr, &csum_off);\n",
    "        ret2 = lb6_rev_nat (ctx, l4_off, & csum_off, ct_state -> rev_nat_index, tuple, 0);\n",
    "        if (IS_ERR (ret2))\n",
    "            return ret2;\n",
    "    }\n",
    "    verdict = policy_can_access_ingress (ctx, src_label, SECLABEL, tuple -> dport, tuple -> nexthdr, false, & policy_match_type, & audited);\n",
    "    if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {\n",
    "        send_policy_verdict_notify (ctx, src_label, tuple->dport, tuple->nexthdr, POLICY_INGRESS, 1, verdict, policy_match_type, audited);\n",
    "        return verdict;\n",
    "    }\n",
    "    if (skip_ingress_proxy) {\n",
    "        verdict = 0;\n",
    "        emit_policy_verdict = false;\n",
    "    }\n",
    "    if (emit_policy_verdict && (ret == CT_NEW || ret == CT_REOPENED)) {\n",
    "        send_policy_verdict_notify (ctx, src_label, tuple->dport, tuple->nexthdr, POLICY_INGRESS, 1, verdict, policy_match_type, audited);\n",
    "    }\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    if (ret == CT_NEW || ret == CT_REOPENED) {\n",
    "        bool dsr = false;\n",
    "\n",
    "# ifdef ENABLE_DSR\n",
    "        int ret2;\n",
    "        ret2 = handle_dsr_v6 (ctx, & dsr);\n",
    "        if (ret2 != 0)\n",
    "            return ret2;\n",
    "        ct_state_new.dsr = dsr;\n",
    "        if (ret == CT_REOPENED && ct_state->dsr != dsr)\n",
    "            ct_update6_dsr (get_ct_map6 (tuple), tuple, dsr);\n",
    "\n",
    "# endif /* ENABLE_DSR */\n",
    "        if (!dsr) {\n",
    "            bool node_port = ct_has_nodeport_egress_entry6 (get_ct_map6 (tuple), tuple);\n",
    "            ct_state_new.node_port = node_port;\n",
    "            if (ret == CT_REOPENED && ct_state->node_port != node_port)\n",
    "                ct_update_nodeport (get_ct_map6 (tuple), tuple, node_port);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "    if (ret == CT_NEW) {\n",
    "        ct_state_new.src_sec_id = src_label;\n",
    "        ret = ct_create6 (get_ct_map6 (tuple), & CT_MAP_ANY6, tuple, ctx, CT_INGRESS, & ct_state_new, verdict > 0, false);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    reason = (enum trace_reason) *ct_status;\n",
    "    if (redirect_to_proxy (verdict, *ct_status)) {\n",
    "        *proxy_port = (__u16) verdict;\n",
    "        send_trace_notify6 (ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip, bpf_ntohs (*proxy_port), ifindex, reason, monitor);\n",
    "        if (tuple_out)\n",
    "            memcpy (tuple_out, tuple, sizeof (*tuple));\n",
    "        return POLICY_ACT_PROXY_REDIRECT;\n",
    "    }\n",
    "    send_trace_notify6 (ctx, TRACE_TO_LXC, src_label, SECLABEL, &orig_sip, LXC_ID, ifindex, reason, monitor);\n",
    "\n",
    "#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)\n",
    "    ctx_change_type (ctx, PACKET_HOST);\n",
    "\n",
    "#else\n",
    "    ifindex = ctx_load_meta (ctx, CB_IFINDEX);\n",
    "    if (ifindex)\n",
    "        return redirect_ep (ctx, ifindex, from_host);\n",
    "\n",
    "#endif /* !ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int
ipv6_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label,
	    enum ct_status *ct_status, struct ipv6_ct_tuple *tuple_out,
	    __u16 *proxy_port, bool from_host __maybe_unused)
{
	struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};
	struct ipv6_ct_tuple tuple_on_stack __maybe_unused, *tuple;
	int ret, verdict, hdrlen, zero = 0;
	struct ct_buffer6 *ct_buffer;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	bool skip_ingress_proxy = false;
	enum trace_reason reason;
	union v6addr orig_sip;
	__u32 monitor = 0;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool emit_policy_verdict = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	policy_clear_mark(ctx);

	ipv6_addr_copy(&orig_sip, (union v6addr *)&ip6->saddr);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER6, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr.d1 == 0 && ct_buffer->tuple.saddr.d2 == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES
	tuple = (struct ipv6_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
#else
	memcpy(&tuple_on_stack, &ct_buffer->tuple, sizeof(tuple_on_stack));
	tuple = &tuple_on_stack;
	memcpy(&ct_state_on_stack, &ct_buffer->ct_state, sizeof(ct_state_on_stack));
	ct_state = &ct_state_on_stack;
#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */
	monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	*ct_status = (enum ct_status)ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 * Always redirect connections that originated from L7 LB.
	 */
	if ((ret == CT_REPLY || ret == CT_RELATED) &&
	    (ct_state_is_from_l7lb(ct_state) ||
	     (ct_state->proxy_redirect && !tc_index_skip_egress_proxy(ctx)))) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				   0, ifindex, (enum trace_reason)ret, monitor);
		if (tuple_out)
			memcpy(tuple_out, tuple, sizeof(*tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}

	if (unlikely(ct_state->rev_nat_index)) {
		struct csum_offset csum_off = {};
		int ret2, l4_off;

		hdrlen = ipv6_hdrlen(ctx, &tuple->nexthdr);
		if (hdrlen < 0)
			return hdrlen;

		l4_off = ETH_HLEN + hdrlen;

		csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

		ret2 = lb6_rev_nat(ctx, l4_off, &csum_off,
				   ct_state->rev_nat_index, tuple, 0);
		if (IS_ERR(ret2))
			return ret2;
	}

	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple->dport, tuple->nexthdr, false,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy) {
		verdict = 0;
		emit_policy_verdict = false;
	}

	if (emit_policy_verdict && (ret == CT_NEW || ret == CT_REOPENED)) {
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 1,
					   verdict, policy_match_type, audited);
	}

#ifdef ENABLE_NODEPORT
	if (ret == CT_NEW || ret == CT_REOPENED) {
		bool dsr = false;
# ifdef ENABLE_DSR
		int ret2;

		ret2 = handle_dsr_v6(ctx, &dsr);
		if (ret2 != 0)
			return ret2;

		ct_state_new.dsr = dsr;
		if (ret == CT_REOPENED && ct_state->dsr != dsr)
			ct_update6_dsr(get_ct_map6(tuple), tuple, dsr);
# endif /* ENABLE_DSR */
		if (!dsr) {
			bool node_port =
				ct_has_nodeport_egress_entry6(get_ct_map6(tuple),
							      tuple);

			ct_state_new.node_port = node_port;
			if (ret == CT_REOPENED &&
			    ct_state->node_port != node_port)
				ct_update_nodeport(get_ct_map6(tuple), tuple,
						   node_port);
		}
	}
#endif /* ENABLE_NODEPORT */

	if (ret == CT_NEW) {
		ct_state_new.src_sec_id = src_label;
		ret = ct_create6(get_ct_map6(tuple), &CT_MAP_ANY6, tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0, false);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	reason = (enum trace_reason)*ct_status;
	if (redirect_to_proxy(verdict, *ct_status)) {
		*proxy_port = (__u16)verdict;
		send_trace_notify6(ctx, TRACE_TO_PROXY, src_label, SECLABEL, &orig_sip,
				   bpf_ntohs(*proxy_port), ifindex, reason, monitor);
		if (tuple_out)
			memcpy(tuple_out, tuple, sizeof(*tuple));
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify6(ctx, TRACE_TO_LXC, src_label, SECLABEL, &orig_sip,
			   LXC_ID, ifindex, reason, monitor);

#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)
	/* See comment in IPv4 path. */
	ctx_change_type(ctx, PACKET_HOST);
#else
	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ctx, ifindex, from_host);
#endif /* !ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool proxy_redirect __maybe_unused ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy6ctx",
          " &tuple",
          " proxy_port",
          " from_host"
        ]
      },
      {
        "opVar": "\t\tproxy_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef ENABLE_CUSTOM_CALLS\t\tif !proxy_ && !encode_custom_prog_metactx",
          " ret",
          " src_label "
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV6_INGRESS"
        ]
      }
    ]
  },
  "startLine": 1540,
  "endLine": 1581,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_ipv6_policy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "int tail_ipv6_policy (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct ipv6_ct_tuple tuple = {}\n",
    "    ;\n",
    "    int ret, ifindex = ctx_load_meta (ctx, CB_IFINDEX);\n",
    "    __u32 src_label = ctx_load_meta (ctx, CB_SRC_LABEL);\n",
    "    bool from_host = ctx_load_meta (ctx, CB_FROM_HOST);\n",
    "    bool proxy_redirect __maybe_unused = false;\n",
    "    __u16 proxy_port = 0;\n",
    "    enum ct_status ct_status = 0;\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, 0);\n",
    "    ctx_store_meta (ctx, CB_FROM_HOST, 0);\n",
    "    ret = ipv6_policy (ctx, ifindex, src_label, & ct_status, & tuple, & proxy_port, from_host);\n",
    "    if (ret == POLICY_ACT_PROXY_REDIRECT) {\n",
    "        ret = ctx_redirect_to_proxy6 (ctx, & tuple, proxy_port, from_host);\n",
    "        proxy_redirect = true;\n",
    "    }\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, src_label, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, ctx->mark);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!proxy_redirect && !encode_custom_prog_meta (ctx, ret, src_label)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV6_INGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_ipv6_policy(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	__u16 proxy_port = 0;
	enum ct_status ct_status = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

	ret = ipv6_policy(ctx, ifindex, src_label, &ct_status, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy6(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
	}
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_TO_ENDPOINT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool proxy_redirect __maybe_unused ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy_hairpin_ipv6ctx",
          " proxy_port"
        ]
      },
      {
        "opVar": "\t\tproxy_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef ENABLE_CUSTOM_CALLS\t\tif !proxy_ &&\t    !encode_custom_prog_metactx",
          " ret",
          " src_identity "
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV6_INGRESS"
        ]
      }
    ]
  },
  "startLine": 1584,
  "endLine": 1659,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_ipv6_to_endpoint",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "int tail_ipv6_to_endpoint (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 src_identity = ctx_load_meta (ctx, CB_SRC_LABEL);\n",
    "    bool proxy_redirect __maybe_unused = false;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    __u16 proxy_port = 0;\n",
    "    enum ct_status ct_status;\n",
    "    int ret;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto out;\n",
    "    }\n",
    "    if (identity_is_reserved (src_identity)) {\n",
    "        union v6addr *src = (union v6addr *) &ip6->saddr;\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = lookup_ip6_remote_endpoint (src);\n",
    "        if (info != NULL) {\n",
    "            __u32 sec_label = info->sec_label;\n",
    "            if (sec_label) {\n",
    "                if (sec_label != HOST_ID)\n",
    "                    src_identity = sec_label;\n",
    "            }\n",
    "        }\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6, ((__u32 *) src)[3], src_identity);\n",
    "    }\n",
    "    cilium_dbg (ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);\n",
    "\n",
    "#ifdef LOCAL_DELIVERY_METRICS\n",
    "    update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_FORWARDED);\n",
    "\n",
    "#endif\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, 0);\n",
    "    ret = ipv6_policy (ctx, 0, src_identity, & ct_status, NULL, & proxy_port, true);\n",
    "    if (ret == POLICY_ACT_PROXY_REDIRECT) {\n",
    "        ret = ctx_redirect_to_proxy_hairpin_ipv6 (ctx, proxy_port);\n",
    "        proxy_redirect = true;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, src_identity, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!proxy_redirect && !encode_custom_prog_meta (ctx, ret, src_identity)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV6_INGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_ipv6_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proxy_port = 0;
	enum ct_status ct_status;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip6)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		union v6addr *src = (union v6addr *)&ip6->saddr;
		struct remote_endpoint_info *info;

		info = lookup_ip6_remote_endpoint(src);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;

			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED6 : DBG_IP_ID_MAP_FAILED6,
			   ((__u32 *)src)[3], src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = ipv6_policy(ctx, 0, src_identity, &ct_status, NULL,
			  &proxy_port, true);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy_hairpin_ipv6(ctx, proxy_port);
		proxy_redirect = true;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_identity)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV6_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY,
		tail_ipv6_ct_ingress_policy_only, CT_INGRESS,
		__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY, tail_ipv6_policy)

TAIL_CT_LOOKUP6(CILIUM_CALL_IPV6_CT_INGRESS, tail_ipv6_ct_ingress, CT_INGRESS,
		1, CILIUM_CALL_IPV6_TO_ENDPOINT, tail_ipv6_to_endpoint)
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
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
    "map_lookup_elem": [
      {
        "opVar": "#endif\tct_buffer ",
        "inpVar": [
          " &CT_TAIL_CALL_BUFFER4",
          " &zero"
        ]
      }
    ],
    "redirect": [
      {
        "opVar": "\tif ((ret ",
        "inpVar": [
          ""
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\tif _to_proxyverdict",
          " *ct_status "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\tif ifindex\t\treturn _epctx",
          " ifindex",
          " from_host"
        ]
      }
    ]
  },
  "startLine": 1671,
  "endLine": 1879,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "ipv4_policy",
  "updateMaps": [],
  "readMaps": [
    "  CT_TAIL_CALL_BUFFER4"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int ifindex",
    " __u32 src_label",
    " enum ct_status *ct_status",
    " struct ipv4_ct_tuple *tuple_out",
    " __u16 *proxy_port",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "static __always_inline int ipv4_policy (struct  __ctx_buff *ctx, int ifindex, __u32 src_label, enum ct_status *ct_status, struct ipv4_ct_tuple *tuple_out, __u16 *proxy_port, bool from_host __maybe_unused)\n",
    "{\n",
    "    struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};\n",
    "    struct ipv4_ct_tuple tuple_on_stack __maybe_unused, *tuple;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    bool skip_ingress_proxy = false;\n",
    "    bool is_untracked_fragment = false;\n",
    "    struct ct_buffer4 *ct_buffer;\n",
    "    __u32 monitor = 0, zero = 0;\n",
    "    enum trace_reason reason;\n",
    "    int ret, verdict = 0;\n",
    "    __be32 orig_sip;\n",
    "    __u8 policy_match_type = POLICY_MATCH_NONE;\n",
    "    __u8 audited = 0;\n",
    "    bool emit_policy_verdict = true;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    policy_clear_mark (ctx);\n",
    "    skip_ingress_proxy = tc_index_skip_ingress_proxy (ctx);\n",
    "    orig_sip = ip4->saddr;\n",
    "\n",
    "#ifndef ENABLE_IPV4_FRAGMENTS\n",
    "    is_untracked_fragment = ipv4_is_fragment (ip4);\n",
    "\n",
    "#endif\n",
    "    ct_buffer = map_lookup_elem (& CT_TAIL_CALL_BUFFER4, & zero);\n",
    "    if (!ct_buffer)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "    if (ct_buffer->tuple.saddr == 0)\n",
    "        return DROP_INVALID_TC_BUFFER;\n",
    "\n",
    "#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES\n",
    "    tuple = (struct ipv4_ct_tuple *) &ct_buffer->tuple;\n",
    "    ct_state = (struct ct_state *) &ct_buffer->ct_state;\n",
    "\n",
    "#else\n",
    "    memcpy (&tuple_on_stack, &ct_buffer->tuple, sizeof (tuple_on_stack));\n",
    "    tuple = &tuple_on_stack;\n",
    "    memcpy (&ct_state_on_stack, &ct_buffer->ct_state, sizeof (ct_state_on_stack));\n",
    "    ct_state = &ct_state_on_stack;\n",
    "\n",
    "#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */\n",
    "    monitor = ct_buffer->monitor;\n",
    "    ret = ct_buffer->ret;\n",
    "    *ct_status = (enum ct_status) ret;\n",
    "    relax_verifier ();\n",
    "    if ((ret == CT_REPLY || ret == CT_RELATED) && (ct_state_is_from_l7lb (ct_state) || (ct_state->proxy_redirect && !tc_index_skip_egress_proxy (ctx)))) {\n",
    "        send_trace_notify4 (ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip, 0, ifindex, (enum trace_reason) ret, monitor);\n",
    "        if (tuple_out)\n",
    "            *tuple_out = *tuple;\n",
    "        return POLICY_ACT_PROXY_REDIRECT;\n",
    "    }\n",
    "    if (unlikely (ret == CT_REPLY && ct_state->rev_nat_index && !ct_state->loopback)) {\n",
    "        struct csum_offset csum_off = {}\n",
    "        ;\n",
    "        bool has_l4_header = false;\n",
    "        int ret2, l4_off;\n",
    "        l4_off = ETH_HLEN + ipv4_hdrlen (ip4);\n",
    "        has_l4_header = ipv4_has_l4_header (ip4);\n",
    "        if (has_l4_header)\n",
    "            csum_l4_offset_and_flags (tuple->nexthdr, &csum_off);\n",
    "        ret2 = lb4_rev_nat (ctx, ETH_HLEN, l4_off, & csum_off, ct_state, tuple, REV_NAT_F_TUPLE_SADDR, has_l4_header);\n",
    "        if (IS_ERR (ret2))\n",
    "            return ret2;\n",
    "    }\n",
    "\n",
    "#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)\n",
    "    if (unlikely (ct_state->loopback))\n",
    "        goto skip_policy_enforcement;\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */\n",
    "    verdict = policy_can_access_ingress (ctx, src_label, SECLABEL, tuple -> dport, tuple -> nexthdr, is_untracked_fragment, & policy_match_type, & audited);\n",
    "    if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {\n",
    "        send_policy_verdict_notify (ctx, src_label, tuple->dport, tuple->nexthdr, POLICY_INGRESS, 0, verdict, policy_match_type, audited);\n",
    "        return verdict;\n",
    "    }\n",
    "    if (skip_ingress_proxy) {\n",
    "        verdict = 0;\n",
    "        emit_policy_verdict = false;\n",
    "    }\n",
    "    if (emit_policy_verdict && (ret == CT_NEW || ret == CT_REOPENED)) {\n",
    "        send_policy_verdict_notify (ctx, src_label, tuple->dport, tuple->nexthdr, POLICY_INGRESS, 0, verdict, policy_match_type, audited);\n",
    "    }\n",
    "\n",
    "#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)\n",
    "skip_policy_enforcement :\n",
    "\n",
    "#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    if (ret == CT_NEW || ret == CT_REOPENED) {\n",
    "        bool dsr = false;\n",
    "\n",
    "# ifdef ENABLE_DSR\n",
    "        int ret2;\n",
    "        ret2 = handle_dsr_v4 (ctx, & dsr);\n",
    "        if (ret2 != 0)\n",
    "            return ret2;\n",
    "        ct_state_new.dsr = dsr;\n",
    "        if (ret == CT_REOPENED && ct_state->dsr != dsr)\n",
    "            ct_update4_dsr (get_ct_map4 (tuple), tuple, dsr);\n",
    "\n",
    "# endif /* ENABLE_DSR */\n",
    "        if (!dsr) {\n",
    "            bool node_port = ct_has_nodeport_egress_entry4 (get_ct_map4 (tuple), tuple);\n",
    "            ct_state_new.node_port = node_port;\n",
    "            if (ret == CT_REOPENED && ct_state->node_port != node_port)\n",
    "                ct_update_nodeport (get_ct_map4 (tuple), tuple, node_port);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "    if (ret == CT_NEW) {\n",
    "        ct_state_new.src_sec_id = src_label;\n",
    "        ret = ct_create4 (get_ct_map4 (tuple), & CT_MAP_ANY4, tuple, ctx, CT_INGRESS, & ct_state_new, verdict > 0, false);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    reason = (enum trace_reason) *ct_status;\n",
    "    if (redirect_to_proxy (verdict, *ct_status)) {\n",
    "        *proxy_port = (__u16) verdict;\n",
    "        send_trace_notify4 (ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip, bpf_ntohs (*proxy_port), ifindex, reason, monitor);\n",
    "        if (tuple_out)\n",
    "            *tuple_out = *tuple;\n",
    "        return POLICY_ACT_PROXY_REDIRECT;\n",
    "    }\n",
    "    send_trace_notify4 (ctx, TRACE_TO_LXC, src_label, SECLABEL, orig_sip, LXC_ID, ifindex, reason, monitor);\n",
    "\n",
    "#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)\n",
    "    ctx_change_type (ctx, PACKET_HOST);\n",
    "\n",
    "#else\n",
    "    ifindex = ctx_load_meta (ctx, CB_IFINDEX);\n",
    "    if (ifindex)\n",
    "        return redirect_ep (ctx, ifindex, from_host);\n",
    "\n",
    "#endif /* !ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
static __always_inline int
ipv4_policy(struct __ctx_buff *ctx, int ifindex, __u32 src_label, enum ct_status *ct_status,
	    struct ipv4_ct_tuple *tuple_out, __u16 *proxy_port,
	    bool from_host __maybe_unused)
{
	struct ct_state ct_state_on_stack __maybe_unused, *ct_state, ct_state_new = {};
	struct ipv4_ct_tuple tuple_on_stack __maybe_unused, *tuple;
	void *data, *data_end;
	struct iphdr *ip4;
	bool skip_ingress_proxy = false;
	bool is_untracked_fragment = false;
	struct ct_buffer4 *ct_buffer;
	__u32 monitor = 0, zero = 0;
	enum trace_reason reason;
	int ret, verdict = 0;
	__be32 orig_sip;
	__u8 policy_match_type = POLICY_MATCH_NONE;
	__u8 audited = 0;
	bool emit_policy_verdict = true;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	policy_clear_mark(ctx);

	/* If packet is coming from the ingress proxy we have to skip
	 * redirection to the ingress proxy as we would loop forever.
	 */
	skip_ingress_proxy = tc_index_skip_ingress_proxy(ctx);

	orig_sip = ip4->saddr;

#ifndef ENABLE_IPV4_FRAGMENTS
	/* Indicate that this is a datagram fragment for which we cannot
	 * retrieve L4 ports. Do not set flag if we support fragmentation.
	 */
	is_untracked_fragment = ipv4_is_fragment(ip4);
#endif

	ct_buffer = map_lookup_elem(&CT_TAIL_CALL_BUFFER4, &zero);
	if (!ct_buffer)
		return DROP_INVALID_TC_BUFFER;
	if (ct_buffer->tuple.saddr == 0)
		/* The map value is zeroed so the map update didn't happen somehow. */
		return DROP_INVALID_TC_BUFFER;

#if HAVE_DIRECT_ACCESS_TO_MAP_VALUES
	tuple = (struct ipv4_ct_tuple *)&ct_buffer->tuple;
	ct_state = (struct ct_state *)&ct_buffer->ct_state;
#else
	memcpy(&tuple_on_stack, &ct_buffer->tuple, sizeof(tuple_on_stack));
	tuple = &tuple_on_stack;
	memcpy(&ct_state_on_stack, &ct_buffer->ct_state, sizeof(ct_state_on_stack));
	ct_state = &ct_state_on_stack;
#endif /* HAVE_DIRECT_ACCESS_TO_MAP_VALUES */
	monitor = ct_buffer->monitor;
	ret = ct_buffer->ret;
	*ct_status = (enum ct_status)ret;

	/* Check it this is return traffic to an egress proxy.
	 * Do not redirect again if the packet is coming from the egress proxy.
	 * Always redirect connections that originated from L7 LB.
	 */
	relax_verifier();
	if ((ret == CT_REPLY || ret == CT_RELATED) &&
	    (ct_state_is_from_l7lb(ct_state) ||
	     (ct_state->proxy_redirect && !tc_index_skip_egress_proxy(ctx)))) {
		/* This is a reply, the proxy port does not need to be embedded
		 * into ctx->mark and *proxy_port can be left unset.
		 */
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				   0, ifindex, (enum trace_reason)ret, monitor);
		if (tuple_out)
			*tuple_out = *tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}

	if (unlikely(ret == CT_REPLY && ct_state->rev_nat_index &&
		     !ct_state->loopback)) {
		struct csum_offset csum_off = {};
		bool has_l4_header = false;
		int ret2, l4_off;

		l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

		has_l4_header = ipv4_has_l4_header(ip4);
		if (has_l4_header)
			csum_l4_offset_and_flags(tuple->nexthdr, &csum_off);

		ret2 = lb4_rev_nat(ctx, ETH_HLEN, l4_off, &csum_off,
				   ct_state, tuple,
				   REV_NAT_F_TUPLE_SADDR, has_l4_header);
		if (IS_ERR(ret2))
			return ret2;
	}

#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)
	/* When an endpoint connects to itself via service clusterIP, we need
	 * to skip the policy enforcement. If we didn't, the user would have to
	 * define policy rules to allow pods to talk to themselves. We still
	 * want to execute the conntrack logic so that replies can be correctly
	 * matched.
	 */
	if (unlikely(ct_state->loopback))
		goto skip_policy_enforcement;
#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */

	verdict = policy_can_access_ingress(ctx, src_label, SECLABEL,
					    tuple->dport, tuple->nexthdr,
					    is_untracked_fragment,
					    &policy_match_type, &audited);

	/* Reply packets and related packets are allowed, all others must be
	 * permitted by policy.
	 */
	if (ret != CT_REPLY && ret != CT_RELATED && verdict < 0) {
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
		return verdict;
	}

	if (skip_ingress_proxy) {
		verdict = 0;
		emit_policy_verdict = false;
	}

	if (emit_policy_verdict && (ret == CT_NEW || ret == CT_REOPENED)) {
		send_policy_verdict_notify(ctx, src_label, tuple->dport,
					   tuple->nexthdr, POLICY_INGRESS, 0,
					   verdict, policy_match_type, audited);
	}

#if defined(ENABLE_PER_PACKET_LB) && !defined(DISABLE_LOOPBACK_LB)
skip_policy_enforcement:
#endif /* ENABLE_PER_PACKET_LB && !DISABLE_LOOPBACK_LB */

#ifdef ENABLE_NODEPORT
	if (ret == CT_NEW || ret == CT_REOPENED) {
		bool dsr = false;
# ifdef ENABLE_DSR
		int ret2;

		ret2 = handle_dsr_v4(ctx, &dsr);
		if (ret2 != 0)
			return ret2;

		ct_state_new.dsr = dsr;
		if (ret == CT_REOPENED && ct_state->dsr != dsr)
			ct_update4_dsr(get_ct_map4(tuple), tuple, dsr);
# endif /* ENABLE_DSR */
		if (!dsr) {
			bool node_port =
				ct_has_nodeport_egress_entry4(get_ct_map4(tuple),
							      tuple);

			ct_state_new.node_port = node_port;
			if (ret == CT_REOPENED &&
			    ct_state->node_port != node_port)
				ct_update_nodeport(get_ct_map4(tuple), tuple,
						   node_port);
		}
	}
#endif /* ENABLE_NODEPORT */

	if (ret == CT_NEW) {
		ct_state_new.src_sec_id = src_label;
		ret = ct_create4(get_ct_map4(tuple), &CT_MAP_ANY4, tuple, ctx, CT_INGRESS,
				 &ct_state_new, verdict > 0, false);
		if (IS_ERR(ret))
			return ret;

		/* NOTE: tuple has been invalidated after this */
	}

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	reason = (enum trace_reason)*ct_status;
	if (redirect_to_proxy(verdict, *ct_status)) {
		*proxy_port = (__u16)verdict;
		send_trace_notify4(ctx, TRACE_TO_PROXY, src_label, SECLABEL, orig_sip,
				   bpf_ntohs(*proxy_port), ifindex, reason, monitor);
		if (tuple_out)
			*tuple_out = *tuple;
		return POLICY_ACT_PROXY_REDIRECT;
	}
	/* Not redirected to host / proxy. */
	send_trace_notify4(ctx, TRACE_TO_LXC, src_label, SECLABEL, orig_sip,
			   LXC_ID, ifindex, reason, monitor);

#if !defined(ENABLE_ROUTING) && defined(TUNNEL_MODE) && !defined(ENABLE_NODEPORT)
	/* In tunneling mode, we execute this code to send the packet from
	 * cilium_vxlan to lxc*. If we're using kube-proxy, we don't want to use
	 * redirect() because that would bypass conntrack and the reverse DNAT.
	 * Thus, we send packets to the stack, but since they have the wrong
	 * Ethernet addresses, we need to mark them as PACKET_HOST or the kernel
	 * will drop them.
	 * See #14646 for details.
	 */
	ctx_change_type(ctx, PACKET_HOST);
#else
	ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	if (ifindex)
		return redirect_ep(ctx, ifindex, from_host);
#endif /* !ENABLE_ROUTING && TUNNEL_MODE && !ENABLE_NODEPORT */

	return CTX_ACT_OK;
}

declare_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		    CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool proxy_redirect __maybe_unused ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy4ctx",
          " &tuple",
          " proxy_port",
          " from_host"
        ]
      },
      {
        "opVar": "\t\tproxy_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef ENABLE_CUSTOM_CALLS\t\tif !proxy_ && !encode_custom_prog_metactx",
          " ret",
          " src_label "
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV4_INGRESS"
        ]
      }
    ]
  },
  "startLine": 1883,
  "endLine": 1924,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_ipv4_policy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "int tail_ipv4_policy (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    int ret, ifindex = ctx_load_meta (ctx, CB_IFINDEX);\n",
    "    __u32 src_label = ctx_load_meta (ctx, CB_SRC_LABEL);\n",
    "    bool from_host = ctx_load_meta (ctx, CB_FROM_HOST);\n",
    "    bool proxy_redirect __maybe_unused = false;\n",
    "    enum ct_status ct_status = 0;\n",
    "    __u16 proxy_port = 0;\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, 0);\n",
    "    ctx_store_meta (ctx, CB_FROM_HOST, 0);\n",
    "    ret = ipv4_policy (ctx, ifindex, src_label, & ct_status, & tuple, & proxy_port, from_host);\n",
    "    if (ret == POLICY_ACT_PROXY_REDIRECT) {\n",
    "        ret = ctx_redirect_to_proxy4 (ctx, & tuple, proxy_port, from_host);\n",
    "        proxy_redirect = true;\n",
    "    }\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, src_label, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, ctx->mark);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!proxy_redirect && !encode_custom_prog_meta (ctx, ret, src_label)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV4_INGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_ipv4_policy(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	int ret, ifindex = ctx_load_meta(ctx, CB_IFINDEX);
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool from_host = ctx_load_meta(ctx, CB_FROM_HOST);
	bool proxy_redirect __maybe_unused = false;
	enum ct_status ct_status = 0;
	__u16 proxy_port = 0;

	ctx_store_meta(ctx, CB_SRC_LABEL, 0);
	ctx_store_meta(ctx, CB_FROM_HOST, 0);

	ret = ipv4_policy(ctx, ifindex, src_label, &ct_status, &tuple,
			  &proxy_port, from_host);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy4(ctx, &tuple, proxy_port, from_host);
		proxy_redirect = true;
	}
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	/* Store meta: essential for proxy ingress, see bpf_host.c */
	ctx_store_meta(ctx, CB_PROXY_MAGIC, ctx->mark);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect && !encode_custom_prog_meta(ctx, ret, src_label)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_TO_ENDPOINT)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "\tbool proxy_redirect __maybe_unused ",
        "inpVar": [
          " false"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy_hairpin_ipv4ctx",
          " proxy_port"
        ]
      },
      {
        "opVar": "\t\tproxy_redirect ",
        "inpVar": [
          " true"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef ENABLE_CUSTOM_CALLS\t\tif !proxy_ &&\t    !encode_custom_prog_metactx",
          " ret",
          " src_identity "
        ]
      }
    ],
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &CUSTOM_CALLS_MAP",
          "\t\t\t\t CUSTOM_CALLS_IDX_IPV4_INGRESS"
        ]
      }
    ]
  },
  "startLine": 1927,
  "endLine": 2001,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "tail_ipv4_to_endpoint",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call",
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "int tail_ipv4_to_endpoint (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 src_identity = ctx_load_meta (ctx, CB_SRC_LABEL);\n",
    "    bool proxy_redirect __maybe_unused = false;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    __u16 proxy_port = 0;\n",
    "    enum ct_status ct_status;\n",
    "    int ret;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4)) {\n",
    "        ret = DROP_INVALID;\n",
    "        goto out;\n",
    "    }\n",
    "    if (identity_is_reserved (src_identity)) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = lookup_ip4_remote_endpoint (ip4 -> saddr);\n",
    "        if (info != NULL) {\n",
    "            __u32 sec_label = info->sec_label;\n",
    "            if (sec_label) {\n",
    "                if (sec_label != HOST_ID)\n",
    "                    src_identity = sec_label;\n",
    "            }\n",
    "        }\n",
    "        cilium_dbg (ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4, ip4->saddr, src_identity);\n",
    "    }\n",
    "    cilium_dbg (ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);\n",
    "\n",
    "#ifdef LOCAL_DELIVERY_METRICS\n",
    "    update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_FORWARDED);\n",
    "\n",
    "#endif\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, 0);\n",
    "    ret = ipv4_policy (ctx, 0, src_identity, & ct_status, NULL, & proxy_port, true);\n",
    "    if (ret == POLICY_ACT_PROXY_REDIRECT) {\n",
    "        ret = ctx_redirect_to_proxy_hairpin_ipv4 (ctx, proxy_port);\n",
    "        proxy_redirect = true;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, src_identity, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "\n",
    "#ifdef ENABLE_CUSTOM_CALLS\n",
    "    if (!proxy_redirect && !encode_custom_prog_meta (ctx, ret, src_identity)) {\n",
    "        tail_call_static (ctx, &CUSTOM_CALLS_MAP, CUSTOM_CALLS_IDX_IPV4_INGRESS);\n",
    "        update_metrics (ctx_full_len (ctx), METRIC_INGRESS, REASON_MISSED_CUSTOM_CALL);\n",
    "    }\n",
    "\n",
    "#endif\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int tail_ipv4_to_endpoint(struct __ctx_buff *ctx)
{
	__u32 src_identity = ctx_load_meta(ctx, CB_SRC_LABEL);
	bool proxy_redirect __maybe_unused = false;
	void *data, *data_end;
	struct iphdr *ip4;
	__u16 proxy_port = 0;
	enum ct_status ct_status;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}

	/* Packets from the proxy will already have a real identity. */
	if (identity_is_reserved(src_identity)) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(ip4->saddr);
		if (info != NULL) {
			__u32 sec_label = info->sec_label;

			if (sec_label) {
				/* When SNAT is enabled on traffic ingressing
				 * into Cilium, all traffic from the world will
				 * have a source IP of the host. It will only
				 * actually be from the host if "src_identity"
				 * (passed into this function) reports the src
				 * as the host. So we can ignore the ipcache
				 * if it reports the source as HOST_ID.
				 */
				if (sec_label != HOST_ID)
					src_identity = sec_label;
			}
		}
		cilium_dbg(ctx, info ? DBG_IP_ID_MAP_SUCCEED4 : DBG_IP_ID_MAP_FAILED4,
			   ip4->saddr, src_identity);
	}

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, LXC_ID, SECLABEL);

#ifdef LOCAL_DELIVERY_METRICS
	update_metrics(ctx_full_len(ctx), METRIC_INGRESS, REASON_FORWARDED);
#endif
	ctx_store_meta(ctx, CB_SRC_LABEL, 0);

	ret = ipv4_policy(ctx, 0, src_identity, &ct_status, NULL,
			  &proxy_port, true);
	if (ret == POLICY_ACT_PROXY_REDIRECT) {
		ret = ctx_redirect_to_proxy_hairpin_ipv4(ctx, proxy_port);
		proxy_redirect = true;
	}
out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

#ifdef ENABLE_CUSTOM_CALLS
	/* Make sure we skip the tail call when the packet is being redirected
	 * to a L7 proxy, to avoid running the custom program twice on the
	 * incoming packet (before redirecting, and on the way back from the
	 * proxy).
	 */
	if (!proxy_redirect &&
	    !encode_custom_prog_meta(ctx, ret, src_identity)) {
		tail_call_static(ctx, &CUSTOM_CALLS_MAP,
				 CUSTOM_CALLS_IDX_IPV4_INGRESS);
		update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
			       REASON_MISSED_CUSTOM_CALL);
	}
#endif

	return ret;
}

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY,
		tail_ipv4_ct_ingress_policy_only, CT_INGRESS,
		__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
		CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY, tail_ipv4_policy)

TAIL_CT_LOOKUP4(CILIUM_CALL_IPV4_CT_INGRESS, tail_ipv4_ct_ingress, CT_INGRESS,
		1, CILIUM_CALL_IPV4_TO_ENDPOINT, tail_ipv4_to_endpoint)
#endif /* ENABLE_IPV4 */

/* Handle policy decisions as the packet makes its way towards the endpoint.
 * Previously, the packet may have come from another local endpoint, another
 * endpoint in the cluster, or from the big blue room (as identified by the
 * contents of ctx / CB_SRC_LABEL. Determine whether the traffic may be
 * passed into the endpoint or if it needs further inspection by a userspace
 * proxy.
 *
 * This program will be tail called to in ipv{4,6}_local_delivery from either
 * bpf_host, bpf_overlay (if coming from the tunnel), or bpf_lxc (if coming
 * from another local pod).
 */
__section_tail(CILIUM_MAP_POLICY, TEMPLATE_LXC_ID)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2024,
  "endLine": 2061,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_policy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int handle_policy (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 src_label = ctx_load_meta (ctx, CB_SRC_LABEL);\n",
    "    __u16 proto;\n",
    "    int ret;\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        invoke_tailcall_if (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY, tail_ipv6_ct_ingress_policy_only);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        invoke_tailcall_if (__and (is_defined (ENABLE_IPV4), is_defined (ENABLE_IPV6)), CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY, tail_ipv4_ct_ingress_policy_only);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, src_label, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int handle_policy(struct __ctx_buff *ctx)
{
	__u32 src_label = ctx_load_meta(ctx, CB_SRC_LABEL);
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY,
				   tail_ipv6_ct_ingress_policy_only);
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		invoke_tailcall_if(__and(is_defined(ENABLE_IPV4), is_defined(ENABLE_IPV6)),
				   CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY,
				   tail_ipv4_ct_ingress_policy_only);
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, src_label, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

/* Handle policy decisions as the packet makes its way from the
 * endpoint.  Previously, the packet has come from the same endpoint,
 * but was redirected to a L7 LB.
 *
 * This program will be tail called from bpf_host for packets sent by
 * a L7 LB.
 */
#if defined(ENABLE_L7_LB)
__section_tail(CILIUM_MAP_EGRESSPOLICY, TEMPLATE_LXC_ID)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef ENABLE_IPV6\tcase bpf_htonsETH_P_IPV6:\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_LXC"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#endif #ifdef ENABLE_IPV4\tcase bpf_htonsETH_P_IP:\t\tep_ctx",
          " CILIUM_CALL_IPV4_FROM_LXC"
        ]
      }
    ]
  },
  "startLine": 2072,
  "endLine": 2113,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_policy_egress",
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
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int handle_policy_egress (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u16 proto;\n",
    "    int ret;\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    ctx_store_meta (ctx, CB_FROM_HOST, FROM_HOST_L7_LB);\n",
    "    edt_set_aggregate (ctx, 0);\n",
    "    send_trace_notify (ctx, TRACE_FROM_PROXY, SECLABEL, 0, 0, 0, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_LXC);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_LXC);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, SECLABEL, 0, LXC_ID, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int handle_policy_egress(struct __ctx_buff *ctx)
{
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	ctx_store_meta(ctx, CB_FROM_HOST, FROM_HOST_L7_LB);

	edt_set_aggregate(ctx, 0); /* do not count this traffic again */
	send_trace_notify(ctx, TRACE_FROM_PROXY, SECLABEL, 0, 0,
			  0 /*ifindex*/,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_LXC);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_LXC);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, SECLABEL, 0, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_EGRESS);

	return ret;
}
#endif

/* Attached to the lxc device on the way to the container, only if endpoint
 * routes are enabled.
 */
__section("to-container")
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
          " &POLICY_EGRESSCALL_MAP",
          " identity"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t_staticctx",
          " &POLICY_CALL_MAP",
          " HOST_EP_ID"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#endif#ifdef ENABLE_IPV6\tcase bpf_htonsETH_P_IPV6:\t\tep_ctx",
          " CILIUM_CALL_IPV6_CT_INGRESS"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#endif #ifdef ENABLE_IPV4\tcase bpf_htonsETH_P_IP:\t\tep_ctx",
          " CILIUM_CALL_IPV4_CT_INGRESS"
        ]
      }
    ]
  },
  "startLine": 2120,
  "endLine": 2195,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c",
  "funcName": "handle_to_container",
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
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int handle_to_container (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    enum trace_point trace = TRACE_FROM_STACK;\n",
    "    __u32 magic, identity = 0;\n",
    "    __u16 proto;\n",
    "    int ret;\n",
    "    if (!validate_ethertype (ctx, &proto)) {\n",
    "        ret = DROP_UNSUPPORTED_L2;\n",
    "        goto out;\n",
    "    }\n",
    "    bpf_clear_meta (ctx);\n",
    "    magic = inherit_identity_from_host (ctx, & identity);\n",
    "    if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)\n",
    "        trace = TRACE_FROM_PROXY;\n",
    "\n",
    "#if defined(ENABLE_L7_LB)\n",
    "    else if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {\n",
    "        tail_call_dynamic (ctx, &POLICY_EGRESSCALL_MAP, identity);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    send_trace_notify (ctx, trace, identity, 0, 0, ctx->ingress_ifindex, TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);\n",
    "\n",
    "#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)\n",
    "    if (identity == HOST_ID) {\n",
    "        ctx_store_meta (ctx, CB_FROM_HOST, 1);\n",
    "        ctx_store_meta (ctx, CB_DST_ENDPOINT_ID, LXC_ID);\n",
    "        tail_call_static (ctx, &POLICY_CALL_MAP, HOST_EP_ID);\n",
    "        return DROP_MISSED_TAIL_CALL;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */\n",
    "    ctx_store_meta (ctx, CB_SRC_LABEL, identity);\n",
    "    switch (proto) {\n",
    "\n",
    "#if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)\n",
    "    case bpf_htons (ETH_P_ARP) :\n",
    "        ret = CTX_ACT_OK;\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV6_CT_INGRESS);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ep_tail_call (ctx, CILIUM_CALL_IPV4_CT_INGRESS);\n",
    "        ret = DROP_MISSED_TAIL_CALL;\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    default :\n",
    "        ret = DROP_UNKNOWN_L3;\n",
    "        break;\n",
    "    }\n",
    "out :\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify (ctx, identity, SECLABEL, LXC_ID, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
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
    {
      "description": " check if the proxy is able to be redirected, and redirect the proxy, store in status. Return true if successful. ",
      "author": "Yihe Bi",
      "authorEmail": "ybi@bu.edu",
      "date": "2023-02-24"
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
int handle_to_container(struct __ctx_buff *ctx)
{
	enum trace_point trace = TRACE_FROM_STACK;
	__u32 magic, identity = 0;
	__u16 proto;
	int ret;

	if (!validate_ethertype(ctx, &proto)) {
		ret = DROP_UNSUPPORTED_L2;
		goto out;
	}

	bpf_clear_meta(ctx);

	magic = inherit_identity_from_host(ctx, &identity);
	if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)
		trace = TRACE_FROM_PROXY;
#if defined(ENABLE_L7_LB)
	else if (magic == MARK_MAGIC_PROXY_EGRESS_EPID) {
		tail_call_dynamic(ctx, &POLICY_EGRESSCALL_MAP, identity);
		return DROP_MISSED_TAIL_CALL;
	}
#endif

	send_trace_notify(ctx, trace, identity, 0, 0, ctx->ingress_ifindex,
			  TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);

#if defined(ENABLE_HOST_FIREWALL) && !defined(ENABLE_ROUTING)
	/* If the packet comes from the hostns and per-endpoint routes are enabled,
	 * jump to bpf_host to enforce egress host policies before anything else.
	 *
	 * We will jump back to bpf_lxc once host policies are enforced. Whenever
	 * we call inherit_identity_from_host, the packet mark is cleared. Thus,
	 * when we jump back, the packet mark will have been cleared and the
	 * identity won't match HOST_ID anymore.
	 */
	if (identity == HOST_ID) {
		ctx_store_meta(ctx, CB_FROM_HOST, 1);
		ctx_store_meta(ctx, CB_DST_ENDPOINT_ID, LXC_ID);
		tail_call_static(ctx, &POLICY_CALL_MAP, HOST_EP_ID);
		return DROP_MISSED_TAIL_CALL;
	}
#endif /* ENABLE_HOST_FIREWALL && !ENABLE_ROUTING */

	ctx_store_meta(ctx, CB_SRC_LABEL, identity);

	switch (proto) {
#if defined(ENABLE_ARP_PASSTHROUGH) || defined(ENABLE_ARP_RESPONDER)
	case bpf_htons(ETH_P_ARP):
		ret = CTX_ACT_OK;
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ep_tail_call(ctx, CILIUM_CALL_IPV6_CT_INGRESS);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ep_tail_call(ctx, CILIUM_CALL_IPV4_CT_INGRESS);
		ret = DROP_MISSED_TAIL_CALL;
		break;
#endif /* ENABLE_IPV4 */
	default:
		ret = DROP_UNKNOWN_L3;
		break;
	}

out:
	if (IS_ERR(ret))
		return send_drop_notify(ctx, identity, SECLABEL, LXC_ID,
					ret, CTX_ACT_DROP, METRIC_INGRESS);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
