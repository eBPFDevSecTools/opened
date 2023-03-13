/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#if !defined(__LIB_ICMP6__) && defined(ENABLE_IPV6)
#define __LIB_ICMP6__

#include <linux/icmpv6.h>
#include <linux/in.h>
#include "common.h"
#include "eth.h"
#include "drop.h"
#include "eps.h"

#define ICMP6_TYPE_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_type))
#define ICMP6_CSUM_OFFSET (sizeof(struct ipv6hdr) + offsetof(struct icmp6hdr, icmp6_cksum))
#define ICMP6_ND_TARGET_OFFSET (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr))
#define ICMP6_ND_OPTS (sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) + sizeof(struct in6_addr))

#define ICMP6_UNREACH_MSG_TYPE		1
#define ICMP6_PARAM_ERR_MSG_TYPE	4
#define ICMP6_ECHO_REQUEST_MSG_TYPE	128
#define ICMP6_ECHO_REPLY_MSG_TYPE	129
#define ICMP6_MULT_LIST_QUERY_TYPE	130
#define ICMP6_NS_MSG_TYPE		135
#define ICMP6_NA_MSG_TYPE		136
#define ICMP6_RR_MSG_TYPE		138
#define ICMP6_INV_NS_MSG_TYPE		141
#define ICMP6_MULT_LIST_REPORT_V2_TYPE	143
#define ICMP6_SEND_NS_MSG_TYPE		148
#define ICMP6_SEND_NA_MSG_TYPE		149
#define ICMP6_MULT_RA_MSG_TYPE		151
#define ICMP6_MULT_RT_MSG_TYPE		153

#define SKIP_HOST_FIREWALL	-2

/* If no specific action is specified, drop unknown neighbour solicitation
 * messages.
 */
#ifndef ACTION_UNKNOWN_ICMP6_NS
#define ACTION_UNKNOWN_ICMP6_NS DROP_UNKNOWN_TARGET
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 43,
  "endLine": 49,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_load_type",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inline__u8",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline __u8 icmp6_load_type (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    __u8 type;\n",
    "    ctx_load_bytes (ctx, nh_off + ICMP6_TYPE_OFFSET, &type, sizeof (type));\n",
    "    return type;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes"
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
static __always_inline __u8 icmp6_load_type(struct __ctx_buff *ctx, int nh_off)
{
	__u8 type;

	ctx_load_bytes(ctx, nh_off + ICMP6_TYPE_OFFSET, &type, sizeof(type));
	return type;
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
  "startLine": 51,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_send_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect",
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "sched_cls",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline int icmp6_send_reply (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    union macaddr smac, dmac = NODE_MAC;\n",
    "    const int csum_off = nh_off + ICMP6_CSUM_OFFSET;\n",
    "    union v6addr sip, dip, router_ip;\n",
    "    __be32 sum;\n",
    "    if (ipv6_load_saddr (ctx, nh_off, &sip) < 0 || ipv6_load_daddr (ctx, nh_off, &dip) < 0)\n",
    "        return DROP_INVALID;\n",
    "    BPF_V6 (router_ip, ROUTER_IP);\n",
    "    if (ipv6_store_saddr (ctx, router_ip.addr, nh_off) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ipv6_store_daddr (ctx, sip.addr, nh_off) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (sip.addr, 16, router_ip.addr, 16, 0);\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    sum = csum_diff (dip.addr, 16, sip.addr, 16, 0);\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    if (eth_load_saddr (ctx, smac.addr, 0) < 0)\n",
    "        return DROP_INVALID;\n",
    "    if (eth_store_daddr (ctx, smac.addr, 0) < 0 || eth_store_saddr (ctx, dmac.addr, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    cilium_dbg_capture (ctx, DBG_CAPTURE_DELIVERY, ctx_get_ifindex (ctx));\n",
    "    return redirect_self (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "eth_load_saddr",
    "ipv6_load_saddr",
    "eth_store_saddr",
    "BPF_V6",
    "eth_store_daddr",
    "cilium_dbg_capture",
    "ipv6_load_daddr",
    "redirect_self",
    "ipv6_store_daddr",
    "ctx_get_ifindex",
    "ipv6_store_saddr"
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
static __always_inline int icmp6_send_reply(struct __ctx_buff *ctx, int nh_off)
{
	union macaddr smac, dmac = NODE_MAC;
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	union v6addr sip, dip, router_ip;
	__be32 sum;

	if (ipv6_load_saddr(ctx, nh_off, &sip) < 0 ||
	    ipv6_load_daddr(ctx, nh_off, &dip) < 0)
		return DROP_INVALID;

	BPF_V6(router_ip, ROUTER_IP);
	/* ctx->saddr = ctx->daddr */
	if (ipv6_store_saddr(ctx, router_ip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;
	/* ctx->daddr = ctx->saddr */
	if (ipv6_store_daddr(ctx, sip.addr, nh_off) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(sip.addr, 16, router_ip.addr, 16, 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	sum = csum_diff(dip.addr, 16, sip.addr, 16, 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* dmac = smac, smac = dmac */
	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
		return DROP_INVALID;

	if (eth_store_daddr(ctx, smac.addr, 0) < 0 ||
	    eth_store_saddr(ctx, dmac.addr, 0) < 0)
		return DROP_WRITE_ERROR;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, ctx_get_ifindex(ctx));

	return redirect_self(ctx);
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
  "startLine": 92,
  "endLine": 125,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "__icmp6_send_echo_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "lwt_in",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int __icmp6_send_echo_reply (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    struct icmp6hdr icmp6hdr __align_stack_8 = {}, icmp6hdr_old  __align_stack_8;\n",
    "    int csum_off = nh_off + ICMP6_CSUM_OFFSET;\n",
    "    __be32 sum;\n",
    "    cilium_dbg (ctx, DBG_ICMP6_REQUEST, nh_off, 0);\n",
    "    if (ctx_load_bytes (ctx, nh_off + sizeof (struct ipv6hdr), &icmp6hdr_old, sizeof (icmp6hdr_old)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    icmp6hdr.icmp6_type = 129;\n",
    "    icmp6hdr.icmp6_code = 0;\n",
    "    icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;\n",
    "    icmp6hdr.icmp6_dataun.un_data32[0] = 0;\n",
    "    icmp6hdr.icmp6_identifier = icmp6hdr_old.icmp6_identifier;\n",
    "    icmp6hdr.icmp6_sequence = icmp6hdr_old.icmp6_sequence;\n",
    "    if (ctx_store_bytes (ctx, nh_off + sizeof (struct ipv6hdr), &icmp6hdr, sizeof (icmp6hdr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (& icmp6hdr_old, sizeof (icmp6hdr_old), & icmp6hdr, sizeof (icmp6hdr), 0);\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return icmp6_send_reply (ctx, nh_off);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes",
    "icmp6_send_reply",
    "cilium_dbg",
    "ctx_load_bytes"
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
static __always_inline int __icmp6_send_echo_reply(struct __ctx_buff *ctx,
						   int nh_off)
{
	struct icmp6hdr icmp6hdr __align_stack_8 = {}, icmp6hdr_old __align_stack_8;
	int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum;

	cilium_dbg(ctx, DBG_ICMP6_REQUEST, nh_off, 0);

	if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return DROP_INVALID;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 129;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;
	icmp6hdr.icmp6_identifier = icmp6hdr_old.icmp6_identifier;
	icmp6hdr.icmp6_sequence = icmp6hdr_old.icmp6_sequence;

	if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr,
			    sizeof(icmp6hdr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksum */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);

	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(ctx, nh_off);
}

#ifndef SKIP_ICMPV6_ECHO_HANDLING
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SEND_ICMP6_ECHO_REPLY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 129,
  "endLine": 139,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "tail_icmp6_send_echo_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "int tail_icmp6_send_echo_reply (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret, nh_off = ctx_load_meta (ctx, 0);\n",
    "    enum metric_dir direction = (enum metric_dir) ctx_load_meta (ctx, 1);\n",
    "    ctx_store_meta (ctx, 0, 0);\n",
    "    ret = __icmp6_send_echo_reply (ctx, nh_off);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, direction);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_meta",
    "ctx_store_meta",
    "IS_ERR",
    "send_drop_notify_error",
    "__icmp6_send_echo_reply"
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
int tail_icmp6_send_echo_reply(struct __ctx_buff *ctx)
{
	int ret, nh_off = ctx_load_meta(ctx, 0);
	enum metric_dir direction  = (enum metric_dir)ctx_load_meta(ctx, 1);

	ctx_store_meta(ctx, 0, 0);
	ret = __icmp6_send_echo_reply(ctx, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, direction);
	return ret;
}
#endif

/*
 * icmp6_send_echo_reply
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 *
 * Send an ICMPv6 echo reply in return to an ICMPv6 echo reply.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 151,
  "endLine": 160,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_send_echo_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int icmp6_send_echo_reply (struct  __ctx_buff *ctx, int nh_off, enum metric_dir direction)\n",
    "{\n",
    "    ctx_store_meta (ctx, 0, nh_off);\n",
    "    ctx_store_meta (ctx, 1, direction);\n",
    "    ep_tail_call (ctx, CILIUM_CALL_SEND_ICMP6_ECHO_REPLY);\n",
    "    return DROP_MISSED_TAIL_CALL;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta",
    "ep_tail_call"
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
static __always_inline int icmp6_send_echo_reply(struct __ctx_buff *ctx,
						 int nh_off, enum metric_dir direction)
{
	ctx_store_meta(ctx, 0, nh_off);
	ctx_store_meta(ctx, 1, direction);

	ep_tail_call(ctx, CILIUM_CALL_SEND_ICMP6_ECHO_REPLY);

	return DROP_MISSED_TAIL_CALL;
}

/*
 * send_icmp6_ndisc_adv
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @mac:	device mac address
 * @to_router:	ndisc is sent to router, otherwise ndisc is sent to an endpoint.
 *
 * Send an ICMPv6 nadv reply in return to an ICMPv6 ndisc.
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
  "startLine": 171,
  "endLine": 232,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "send_icmp6_ndisc_adv",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " union macaddr *mac",
    " bool to_router"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "lwt_in",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int send_icmp6_ndisc_adv (struct  __ctx_buff *ctx, int nh_off, union macaddr *mac, bool to_router)\n",
    "{\n",
    "    struct icmp6hdr icmp6hdr __align_stack_8 = {}, icmp6hdr_old  __align_stack_8;\n",
    "    __u8 opts [8], opts_old [8];\n",
    "    const int csum_off = nh_off + ICMP6_CSUM_OFFSET;\n",
    "    __be32 sum;\n",
    "    if (ctx_load_bytes (ctx, nh_off + sizeof (struct ipv6hdr), &icmp6hdr_old, sizeof (icmp6hdr_old)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    icmp6hdr.icmp6_type = 136;\n",
    "    icmp6hdr.icmp6_code = 0;\n",
    "    icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;\n",
    "    icmp6hdr.icmp6_dataun.un_data32[0] = 0;\n",
    "    if (to_router) {\n",
    "        icmp6hdr.icmp6_router = 1;\n",
    "        icmp6hdr.icmp6_solicited = 1;\n",
    "        icmp6hdr.icmp6_override = 0;\n",
    "    }\n",
    "    else {\n",
    "        icmp6hdr.icmp6_router = 0;\n",
    "        icmp6hdr.icmp6_solicited = 1;\n",
    "        icmp6hdr.icmp6_override = 1;\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, nh_off + sizeof (struct ipv6hdr), &icmp6hdr, sizeof (icmp6hdr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (& icmp6hdr_old, sizeof (icmp6hdr_old), & icmp6hdr, sizeof (icmp6hdr), 0);\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    if (ctx_load_bytes (ctx, nh_off + ICMP6_ND_OPTS, opts_old, sizeof (opts_old)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    opts[0] = 2;\n",
    "    opts[1] = 1;\n",
    "    opts[2] = mac->addr[0];\n",
    "    opts[3] = mac->addr[1];\n",
    "    opts[4] = mac->addr[2];\n",
    "    opts[5] = mac->addr[3];\n",
    "    opts[6] = mac->addr[4];\n",
    "    opts[7] = mac->addr[5];\n",
    "    if (ctx_store_bytes (ctx, nh_off + ICMP6_ND_OPTS, opts, sizeof (opts), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (opts_old, sizeof (opts_old), opts, sizeof (opts), 0);\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return icmp6_send_reply (ctx, nh_off);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_bytes",
    "icmp6_send_reply",
    "ctx_load_bytes"
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
static __always_inline int send_icmp6_ndisc_adv(struct __ctx_buff *ctx,
						int nh_off, union macaddr *mac, bool to_router)
{
	struct icmp6hdr icmp6hdr __align_stack_8 = {}, icmp6hdr_old __align_stack_8;
	__u8 opts[8], opts_old[8];
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum;

	if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr_old,
			   sizeof(icmp6hdr_old)) < 0)
		return DROP_INVALID;

	/* fill icmp6hdr */
	icmp6hdr.icmp6_type = 136;
	icmp6hdr.icmp6_code = 0;
	icmp6hdr.icmp6_cksum = icmp6hdr_old.icmp6_cksum;
	icmp6hdr.icmp6_dataun.un_data32[0] = 0;

	if (to_router) {
		icmp6hdr.icmp6_router = 1;
		icmp6hdr.icmp6_solicited = 1;
		icmp6hdr.icmp6_override = 0;
	} else {
		icmp6hdr.icmp6_router = 0;
		icmp6hdr.icmp6_solicited = 1;
		icmp6hdr.icmp6_override = 1;
	}

	if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr), &icmp6hdr,
			    sizeof(icmp6hdr), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksums */
	sum = csum_diff(&icmp6hdr_old, sizeof(icmp6hdr_old),
			&icmp6hdr, sizeof(icmp6hdr), 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	/* get old options */
	if (ctx_load_bytes(ctx, nh_off + ICMP6_ND_OPTS, opts_old, sizeof(opts_old)) < 0)
		return DROP_INVALID;

	opts[0] = 2;
	opts[1] = 1;
	opts[2] = mac->addr[0];
	opts[3] = mac->addr[1];
	opts[4] = mac->addr[2];
	opts[5] = mac->addr[3];
	opts[6] = mac->addr[4];
	opts[7] = mac->addr[5];

	/* store ND_OPT_TARGET_LL_ADDR option */
	if (ctx_store_bytes(ctx, nh_off + ICMP6_ND_OPTS, opts, sizeof(opts), 0) < 0)
		return DROP_WRITE_ERROR;

	/* fixup checksum */
	sum = csum_diff(opts_old, sizeof(opts_old), opts, sizeof(opts), 0);
	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(ctx, nh_off);
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
  "startLine": 234,
  "endLine": 244,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "compute_icmp6_csum",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "char data [80]",
    " __u16 payload_len",
    " struct ipv6hdr *ipv6hdr"
  ],
  "output": "static__always_inline__be32",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "lwt_in",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __be32 compute_icmp6_csum (char data [80], __u16 payload_len, struct ipv6hdr *ipv6hdr)\n",
    "{\n",
    "    __be32 sum;\n",
    "    sum = csum_diff (NULL, 0, data, payload_len, 0);\n",
    "    sum = ipv6_pseudohdr_checksum (ipv6hdr, IPPROTO_ICMPV6, payload_len, sum);\n",
    "    return sum;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_pseudohdr_checksum"
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
static __always_inline __be32 compute_icmp6_csum(char data[80], __u16 payload_len,
						 struct ipv6hdr *ipv6hdr)
{
	__be32 sum;

	/* compute checksum with new payload length */
	sum = csum_diff(NULL, 0, data, payload_len, 0);
	sum = ipv6_pseudohdr_checksum(ipv6hdr, IPPROTO_ICMPV6, payload_len,
				      sum);
	return sum;
}

#ifdef BPF_HAVE_CHANGE_TAIL
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 247,
  "endLine": 327,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "__icmp6_send_time_exceeded",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int __icmp6_send_time_exceeded (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    char data [80] = {};\n",
    "    struct icmp6hdr *icmp6hoplim;\n",
    "    struct ipv6hdr *ipv6hdr;\n",
    "    char *upper;\n",
    "    const int csum_off = nh_off + ICMP6_CSUM_OFFSET;\n",
    "    __be32 sum = 0;\n",
    "    __u16 payload_len = 0;\n",
    "    __u8 icmp6_nexthdr = IPPROTO_ICMPV6;\n",
    "    int trimlen;\n",
    "    icmp6hoplim = (struct icmp6hdr *) data;\n",
    "    ipv6hdr = (struct ipv6hdr *) (data + 8);\n",
    "    upper = (data + 48);\n",
    "    icmp6hoplim->icmp6_type = 3;\n",
    "    icmp6hoplim->icmp6_code = 0;\n",
    "    icmp6hoplim->icmp6_cksum = 0;\n",
    "    icmp6hoplim->icmp6_dataun.un_data32[0] = 0;\n",
    "    cilium_dbg (ctx, DBG_ICMP6_TIME_EXCEEDED, 0, 0);\n",
    "    if (ctx_load_bytes (ctx, nh_off, ipv6hdr, sizeof (*ipv6hdr)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    if (ipv6_store_nexthdr (ctx, &icmp6_nexthdr, nh_off) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    switch (ipv6hdr->nexthdr) {\n",
    "    case IPPROTO_ICMPV6 :\n",
    "    case IPPROTO_UDP :\n",
    "        if (ctx_load_bytes (ctx, nh_off + sizeof (struct ipv6hdr), upper, 8) < 0)\n",
    "            return DROP_INVALID;\n",
    "        sum = compute_icmp6_csum (data, 56, ipv6hdr);\n",
    "        payload_len = bpf_htons (56);\n",
    "        trimlen = 56 - bpf_ntohs (ipv6hdr->payload_len);\n",
    "        if (ctx_change_tail (ctx, ctx_full_len (ctx) + trimlen, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        if (ctx_store_bytes (ctx, nh_off + sizeof (struct ipv6hdr), data, 56, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        if (ipv6_store_paylen (ctx, nh_off, &payload_len) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        break;\n",
    "    case IPPROTO_TCP :\n",
    "        if (ctx_load_bytes (ctx, nh_off + sizeof (struct ipv6hdr), upper, 20) < 0)\n",
    "            return DROP_INVALID;\n",
    "        sum = compute_icmp6_csum (data, 68, ipv6hdr);\n",
    "        payload_len = bpf_htons (68);\n",
    "        trimlen = 68 - bpf_ntohs (ipv6hdr->payload_len);\n",
    "        if (ctx_change_tail (ctx, ctx_full_len (ctx) + trimlen, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        if (ctx_store_bytes (ctx, nh_off + sizeof (struct ipv6hdr), data, 68, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        if (ipv6_store_paylen (ctx, nh_off, &payload_len) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_L4;\n",
    "    }\n",
    "    if (l4_csum_replace (ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return icmp6_send_reply (ctx, nh_off);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_change_tail",
    "ctx_store_bytes",
    "ipv6_store_nexthdr",
    "compute_icmp6_csum",
    "ctx_full_len",
    "ipv6_store_paylen",
    "cilium_dbg",
    "bpf_htons",
    "bpf_ntohs",
    "icmp6_send_reply",
    "ctx_load_bytes"
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
static __always_inline int __icmp6_send_time_exceeded(struct __ctx_buff *ctx,
						      int nh_off)
{
	/* FIXME: Fix code below to not require this init */
	char data[80] = {};
	struct icmp6hdr *icmp6hoplim;
	struct ipv6hdr *ipv6hdr;
	char *upper; /* icmp6 or tcp or udp */
	const int csum_off = nh_off + ICMP6_CSUM_OFFSET;
	__be32 sum = 0;
	__u16 payload_len = 0; /* FIXME: Uninit of this causes verifier bug */
	__u8 icmp6_nexthdr = IPPROTO_ICMPV6;
	int trimlen;

	/* initialize pointers to offsets in data */
	icmp6hoplim = (struct icmp6hdr *)data;
	ipv6hdr = (struct ipv6hdr *)(data + 8);
	upper = (data + 48);

	/* fill icmp6hdr */
	icmp6hoplim->icmp6_type = 3;
	icmp6hoplim->icmp6_code = 0;
	icmp6hoplim->icmp6_cksum = 0;
	icmp6hoplim->icmp6_dataun.un_data32[0] = 0;

	cilium_dbg(ctx, DBG_ICMP6_TIME_EXCEEDED, 0, 0);

	/* read original v6 hdr into offset 8 */
	if (ctx_load_bytes(ctx, nh_off, ipv6hdr, sizeof(*ipv6hdr)) < 0)
		return DROP_INVALID;

	if (ipv6_store_nexthdr(ctx, &icmp6_nexthdr, nh_off) < 0)
		return DROP_WRITE_ERROR;

	/* read original v6 payload into offset 48 */
	switch (ipv6hdr->nexthdr) {
	case IPPROTO_ICMPV6:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				   upper, 8) < 0)
			return DROP_INVALID;
		sum = compute_icmp6_csum(data, 56, ipv6hdr);
		payload_len = bpf_htons(56);
		trimlen = 56 - bpf_ntohs(ipv6hdr->payload_len);
		if (ctx_change_tail(ctx, ctx_full_len(ctx) + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		/* trim or expand buffer and copy data buffer after ipv6 header */
		if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				    data, 56, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(ctx, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

		break;
		/* copy header without options */
	case IPPROTO_TCP:
		if (ctx_load_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				   upper, 20) < 0)
			return DROP_INVALID;
		sum = compute_icmp6_csum(data, 68, ipv6hdr);
		payload_len = bpf_htons(68);
		/* trim or expand buffer and copy data buffer after ipv6 header */
		trimlen = 68 - bpf_ntohs(ipv6hdr->payload_len);
		if (ctx_change_tail(ctx, ctx_full_len(ctx) + trimlen, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ctx_store_bytes(ctx, nh_off + sizeof(struct ipv6hdr),
				    data, 68, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ipv6_store_paylen(ctx, nh_off, &payload_len) < 0)
			return DROP_WRITE_ERROR;

		break;
	default:
		return DROP_UNKNOWN_L4;
	}

	if (l4_csum_replace(ctx, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return icmp6_send_reply(ctx, nh_off);
}
#endif

#ifndef SKIP_ICMPV6_HOPLIMIT_HANDLING
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 332,
  "endLine": 347,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "tail_icmp6_send_time_exceeded",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "int tail_icmp6_send_time_exceeded (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "# ifdef BPF_HAVE_CHANGE_TAIL\n",
    "    int ret, nh_off = ctx_load_meta (ctx, 0);\n",
    "    enum metric_dir direction = (enum metric_dir) ctx_load_meta (ctx, 1);\n",
    "    ctx_store_meta (ctx, 0, 0);\n",
    "    ret = __icmp6_send_time_exceeded (ctx, nh_off);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, direction);\n",
    "    return ret;\n",
    "\n",
    "# else\n",
    "    return 0;\n",
    "\n",
    "# endif\n",
    "}\n"
  ],
  "called_function_list": [
    "__icmp6_send_time_exceeded",
    "ctx_load_meta",
    "ctx_store_meta",
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
int tail_icmp6_send_time_exceeded(struct __ctx_buff *ctx __maybe_unused)
{
# ifdef BPF_HAVE_CHANGE_TAIL
	int ret, nh_off = ctx_load_meta(ctx, 0);
	enum metric_dir direction  = (enum metric_dir)ctx_load_meta(ctx, 1);

	ctx_store_meta(ctx, 0, 0);
	ret = __icmp6_send_time_exceeded(ctx, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
					      direction);
	return ret;
# else
	return 0;
# endif
}
#endif

/*
 * icmp6_send_time_exceeded
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet (can be ingress or egress)
 * Send a ICMPv6 time exceeded in response to an IPv6 frame.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 359,
  "endLine": 368,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_send_time_exceeded",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int icmp6_send_time_exceeded (struct  __ctx_buff *ctx, int nh_off, enum metric_dir direction)\n",
    "{\n",
    "    ctx_store_meta (ctx, 0, nh_off);\n",
    "    ctx_store_meta (ctx, 1, direction);\n",
    "    ep_tail_call (ctx, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED);\n",
    "    return DROP_MISSED_TAIL_CALL;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta",
    "ep_tail_call"
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
static __always_inline int icmp6_send_time_exceeded(struct __ctx_buff *ctx,
						    int nh_off, enum metric_dir direction)
{
	ctx_store_meta(ctx, 0, nh_off);
	ctx_store_meta(ctx, 1, direction);

	ep_tail_call(ctx, CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED);

	return DROP_MISSED_TAIL_CALL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 370,
  "endLine": 398,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "__icmp6_handle_ns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int __icmp6_handle_ns (struct  __ctx_buff *ctx, int nh_off)\n",
    "{\n",
    "    union v6addr target, router;\n",
    "    struct endpoint_info *ep;\n",
    "    if (ctx_load_bytes (ctx, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr, sizeof (((struct ipv6hdr *) NULL)->saddr)) < 0)\n",
    "        return DROP_INVALID;\n",
    "    cilium_dbg (ctx, DBG_ICMP6_NS, target.p3, target.p4);\n",
    "    BPF_V6 (router, ROUTER_IP);\n",
    "    if (ipv6_addrcmp (&target, &router) == 0) {\n",
    "        union macaddr router_mac = NODE_MAC;\n",
    "        return send_icmp6_ndisc_adv (ctx, nh_off, &router_mac, true);\n",
    "    }\n",
    "    ep = __lookup_ip6_endpoint (& target);\n",
    "    if (ep) {\n",
    "        union macaddr router_mac = NODE_MAC;\n",
    "        return send_icmp6_ndisc_adv (ctx, nh_off, &router_mac, false);\n",
    "    }\n",
    "    return ACTION_UNKNOWN_ICMP6_NS;\n",
    "}\n"
  ],
  "called_function_list": [
    "BPF_V6",
    "__lookup_ip6_endpoint",
    "ipv6_addrcmp",
    "cilium_dbg",
    "send_icmp6_ndisc_adv",
    "ctx_load_bytes"
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
static __always_inline int __icmp6_handle_ns(struct __ctx_buff *ctx, int nh_off)
{
	union v6addr target, router;
	struct endpoint_info *ep;

	if (ctx_load_bytes(ctx, nh_off + ICMP6_ND_TARGET_OFFSET, target.addr,
			   sizeof(((struct ipv6hdr *)NULL)->saddr)) < 0)
		return DROP_INVALID;

	cilium_dbg(ctx, DBG_ICMP6_NS, target.p3, target.p4);

	BPF_V6(router, ROUTER_IP);

	if (ipv6_addrcmp(&target, &router) == 0) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(ctx, nh_off, &router_mac, true);
	}

	ep = __lookup_ip6_endpoint(&target);
	if (ep) {
		union macaddr router_mac = NODE_MAC;

		return send_icmp6_ndisc_adv(ctx, nh_off, &router_mac, false);
	}

	/* Unknown target address, drop */
	return ACTION_UNKNOWN_ICMP6_NS;
}

#ifndef SKIP_ICMPV6_NS_HANDLING
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_HANDLE_ICMP6_NS)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 402,
  "endLine": 412,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "tail_icmp6_handle_ns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "int tail_icmp6_handle_ns (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret, nh_off = ctx_load_meta (ctx, 0);\n",
    "    enum metric_dir direction = (enum metric_dir) ctx_load_meta (ctx, 1);\n",
    "    ctx_store_meta (ctx, 0, 0);\n",
    "    ret = __icmp6_handle_ns (ctx, nh_off);\n",
    "    if (IS_ERR (ret))\n",
    "        return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, direction);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "__icmp6_handle_ns",
    "ctx_load_meta",
    "ctx_store_meta",
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
int tail_icmp6_handle_ns(struct __ctx_buff *ctx)
{
	int ret, nh_off = ctx_load_meta(ctx, 0);
	enum metric_dir direction  = (enum metric_dir)ctx_load_meta(ctx, 1);

	ctx_store_meta(ctx, 0, 0);
	ret = __icmp6_handle_ns(ctx, nh_off);
	if (IS_ERR(ret))
		return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, direction);
	return ret;
}
#endif

/*
 * icmp6_handle_ns
 * @ctx:	socket buffer
 * @nh_off:	offset to the IPv6 header
 * @direction:  direction of packet(ingress or egress)
 *
 * Respond to ICMPv6 Neighbour Solicitation
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 425,
  "endLine": 434,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_handle_ns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int icmp6_handle_ns (struct  __ctx_buff *ctx, int nh_off, enum metric_dir direction)\n",
    "{\n",
    "    ctx_store_meta (ctx, 0, nh_off);\n",
    "    ctx_store_meta (ctx, 1, direction);\n",
    "    ep_tail_call (ctx, CILIUM_CALL_HANDLE_ICMP6_NS);\n",
    "    return DROP_MISSED_TAIL_CALL;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta",
    "ep_tail_call"
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
static __always_inline int icmp6_handle_ns(struct __ctx_buff *ctx, int nh_off,
					   enum metric_dir direction)
{
	ctx_store_meta(ctx, 0, nh_off);
	ctx_store_meta(ctx, 1, direction);

	ep_tail_call(ctx, CILIUM_CALL_HANDLE_ICMP6_NS);

	return DROP_MISSED_TAIL_CALL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 436,
  "endLine": 458,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_handle",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int nh_off",
    " struct ipv6hdr *ip6",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int icmp6_handle (struct  __ctx_buff *ctx, int nh_off, struct ipv6hdr *ip6, enum metric_dir direction)\n",
    "{\n",
    "    union v6addr router_ip;\n",
    "    __u8 type = icmp6_load_type (ctx, nh_off);\n",
    "    cilium_dbg (ctx, DBG_ICMP6_HANDLE, type, 0);\n",
    "    BPF_V6 (router_ip, ROUTER_IP);\n",
    "    switch (type) {\n",
    "    case ICMP6_NS_MSG_TYPE :\n",
    "        return icmp6_handle_ns (ctx, nh_off, direction);\n",
    "    case ICMPV6_ECHO_REQUEST :\n",
    "        if (!ipv6_addrcmp ((union v6addr *) &ip6->daddr, &router_ip))\n",
    "            return icmp6_send_echo_reply (ctx, nh_off, direction);\n",
    "        break;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "icmp6_handle_ns",
    "BPF_V6",
    "icmp6_load_type",
    "icmp6_send_echo_reply",
    "ipv6_addrcmp",
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
static __always_inline int icmp6_handle(struct __ctx_buff *ctx, int nh_off,
					struct ipv6hdr *ip6, enum metric_dir direction)
{
	union v6addr router_ip;
	__u8 type = icmp6_load_type(ctx, nh_off);

	cilium_dbg(ctx, DBG_ICMP6_HANDLE, type, 0);
	BPF_V6(router_ip, ROUTER_IP);

	switch (type) {
	case ICMP6_NS_MSG_TYPE:
		return icmp6_handle_ns(ctx, nh_off, direction);
	case ICMPV6_ECHO_REQUEST:
		if (!ipv6_addrcmp((union v6addr *) &ip6->daddr, &router_ip))
			return icmp6_send_echo_reply(ctx, nh_off, direction);
		break;
	}

	/* All branching above will have issued a tail call, all
	 * remaining traffic is subject to forwarding to containers.
	 */
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
    }
  ],
  "helperCallParams": {},
  "startLine": 460,
  "endLine": 531,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/icmp6.h",
  "funcName": "icmp6_host_handle",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int icmp6_host_handle (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    __u8 type __maybe_unused;\n",
    "    type = icmp6_load_type (ctx, ETH_HLEN);\n",
    "    if (type == ICMP6_NS_MSG_TYPE)\n",
    "        return icmp6_handle_ns (ctx, ETH_HLEN, METRIC_INGRESS);\n",
    "\n",
    "#ifdef ENABLE_HOST_FIREWALL\n",
    "    if (type == ICMP6_ECHO_REQUEST_MSG_TYPE || type == ICMP6_ECHO_REPLY_MSG_TYPE)\n",
    "        return CTX_ACT_OK;\n",
    "    if ((ICMP6_UNREACH_MSG_TYPE <= type && type <= ICMP6_PARAM_ERR_MSG_TYPE) || (ICMP6_MULT_LIST_QUERY_TYPE <= type && type <= ICMP6_NA_MSG_TYPE) || (ICMP6_INV_NS_MSG_TYPE <= type && type <= ICMP6_MULT_LIST_REPORT_V2_TYPE) || (ICMP6_SEND_NS_MSG_TYPE <= type && type <= ICMP6_SEND_NA_MSG_TYPE) || (ICMP6_MULT_RA_MSG_TYPE <= type && type <= ICMP6_MULT_RT_MSG_TYPE))\n",
    "        return SKIP_HOST_FIREWALL;\n",
    "    return DROP_FORBIDDEN_ICMP6;\n",
    "\n",
    "#else\n",
    "    return CTX_ACT_OK;\n",
    "\n",
    "#endif /* ENABLE_HOST_FIREWALL */\n",
    "}\n"
  ],
  "called_function_list": [
    "icmp6_handle_ns",
    "icmp6_load_type"
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
icmp6_host_handle(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 type __maybe_unused;

	type = icmp6_load_type(ctx, ETH_HLEN);
	if (type == ICMP6_NS_MSG_TYPE)
		return icmp6_handle_ns(ctx, ETH_HLEN, METRIC_INGRESS);

#ifdef ENABLE_HOST_FIREWALL
	/* When the host firewall is enabled, we drop and allow ICMPv6 messages
	 * according to RFC4890, except for echo request and reply messages which
	 * are handled by host policies and can be dropped.
	 * |          ICMPv6 Message         |     Action      | Type |
	 * |---------------------------------|-----------------|------|
	 * |          ICMPv6-unreach         |   CTX_ACT_OK    |   1  |
	 * |          ICMPv6-too-big         |   CTX_ACT_OK    |   2  |
	 * |           ICMPv6-timed          |   CTX_ACT_OK    |   3  |
	 * |         ICMPv6-parameter        |   CTX_ACT_OK    |   4  |
	 * |    ICMPv6-err-private-exp-100   |  CTX_ACT_DROP   |  100 |
	 * |    ICMPv6-err-private-exp-101   |  CTX_ACT_DROP   |  101 |
	 * |       ICMPv6-err-expansion      |  CTX_ACT_DROP   |  127 |
	 * |       ICMPv6-echo-message       |    Firewall     |  128 |
	 * |        ICMPv6-echo-reply        |    Firewall     |  129 |
	 * |      ICMPv6-mult-list-query     |   CTX_ACT_OK    |  130 |
	 * |      ICMPv6-mult-list-report    |   CTX_ACT_OK    |  131 |
	 * |      ICMPv6-mult-list-done      |   CTX_ACT_OK    |  132 |
	 * |      ICMPv6-router-solici       |   CTX_ACT_OK    |  133 |
	 * |      ICMPv6-router-advert       |   CTX_ACT_OK    |  134 |
	 * |     ICMPv6-neighbor-solicit     | icmp6_handle_ns |  135 |
	 * |      ICMPv6-neighbor-advert     |   CTX_ACT_OK    |  136 |
	 * |     ICMPv6-redirect-message     |  CTX_ACT_DROP   |  137 |
	 * |      ICMPv6-router-renumber     |   CTX_ACT_OK    |  138 |
	 * |      ICMPv6-node-info-query     |  CTX_ACT_DROP   |  139 |
	 * |     ICMPv6-node-info-response   |  CTX_ACT_DROP   |  140 |
	 * |   ICMPv6-inv-neighbor-solicit   |   CTX_ACT_OK    |  141 |
	 * |    ICMPv6-inv-neighbor-advert   |   CTX_ACT_OK    |  142 |
	 * |    ICMPv6-mult-list-report-v2   |   CTX_ACT_OK    |  143 |
	 * | ICMPv6-home-agent-disco-request |  CTX_ACT_DROP   |  144 |
	 * |  ICMPv6-home-agent-disco-reply  |  CTX_ACT_DROP   |  145 |
	 * |      ICMPv6-mobile-solicit      |  CTX_ACT_DROP   |  146 |
	 * |      ICMPv6-mobile-advert       |  CTX_ACT_DROP   |  147 |
	 * |      ICMPv6-send-solicit        |   CTX_ACT_OK    |  148 |
	 * |       ICMPv6-send-advert        |   CTX_ACT_OK    |  149 |
	 * |       ICMPv6-mobile-exp         |  CTX_ACT_DROP   |  150 |
	 * |    ICMPv6-mult-router-advert    |   CTX_ACT_OK    |  151 |
	 * |    ICMPv6-mult-router-solicit   |   CTX_ACT_OK    |  152 |
	 * |     ICMPv6-mult-router-term     |   CTX_ACT_OK    |  153 |
	 * |         ICMPv6-FMIPv6           |  CTX_ACT_DROP   |  154 |
	 * |       ICMPv6-rpl-control        |  CTX_ACT_DROP   |  155 |
	 * |   ICMPv6-info-private-exp-200   |  CTX_ACT_DROP   |  200 |
	 * |   ICMPv6-info-private-exp-201   |  CTX_ACT_DROP   |  201 |
	 * |      ICMPv6-info-expansion      |  CTX_ACT_DROP   |  255 |
	 * |       ICMPv6-unallocated        |  CTX_ACT_DROP   |      |
	 * |       ICMPv6-unassigned         |  CTX_ACT_DROP   |      |
	 */

	if (type == ICMP6_ECHO_REQUEST_MSG_TYPE || type == ICMP6_ECHO_REPLY_MSG_TYPE)
		/* Decision is deferred to the host policies. */
		return CTX_ACT_OK;

	if ((ICMP6_UNREACH_MSG_TYPE <= type && type <= ICMP6_PARAM_ERR_MSG_TYPE) ||
		(ICMP6_MULT_LIST_QUERY_TYPE <= type && type <= ICMP6_NA_MSG_TYPE) ||
		(ICMP6_INV_NS_MSG_TYPE <= type && type <= ICMP6_MULT_LIST_REPORT_V2_TYPE) ||
		(ICMP6_SEND_NS_MSG_TYPE <= type && type <= ICMP6_SEND_NA_MSG_TYPE) ||
		(ICMP6_MULT_RA_MSG_TYPE <= type && type <= ICMP6_MULT_RT_MSG_TYPE))
		return SKIP_HOST_FIREWALL;
	return DROP_FORBIDDEN_ICMP6;
#else
	return CTX_ACT_OK;
#endif /* ENABLE_HOST_FIREWALL */
}

#endif
