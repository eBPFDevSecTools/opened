/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENCRYPT_H_
#define __LIB_ENCRYPT_H_

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "lib/common.h"

#ifdef ENABLE_IPSEC
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "#else\treturn ctx_ctx",
          " CILIUM_IFINDEX",
          " 0"
        ]
      }
    ]
  },
  "startLine": 15,
  "endLine": 75,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/encrypt.h",
  "funcName": "do_decrypt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 proto"
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
    "static __always_inline int do_decrypt (struct  __ctx_buff *ctx, __u16 proto)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    __u8 protocol = 0;\n",
    "    bool decrypted;\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    struct ipv6hdr *ip6;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    struct iphdr *ip4;\n",
    "\n",
    "#endif\n",
    "    decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        if (!revalidate_data_pull (ctx, &data, &data_end, &ip6)) {\n",
    "            ctx->mark = 0;\n",
    "            return CTX_ACT_OK;\n",
    "        }\n",
    "        protocol = ip6->nexthdr;\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        if (!revalidate_data_pull (ctx, &data, &data_end, &ip4)) {\n",
    "            ctx->mark = 0;\n",
    "            return CTX_ACT_OK;\n",
    "        }\n",
    "        protocol = ip4->protocol;\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "    default :\n",
    "        return CTX_ACT_OK;\n",
    "    }\n",
    "    if (!decrypted) {\n",
    "        if (protocol != IPPROTO_ESP)\n",
    "            return CTX_ACT_OK;\n",
    "        ctx->mark = MARK_MAGIC_DECRYPT;\n",
    "        ctx_change_type (ctx, PACKET_HOST);\n",
    "        return CTX_ACT_OK;\n",
    "    }\n",
    "    ctx->mark = 0;\n",
    "\n",
    "#ifdef ENABLE_ENDPOINT_ROUTES\n",
    "    return CTX_ACT_OK;\n",
    "\n",
    "#else\n",
    "    return ctx_redirect (ctx, CILIUM_IFINDEX, 0);\n",
    "\n",
    "#endif /* ENABLE_ROUTING */\n",
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
do_decrypt(struct __ctx_buff *ctx, __u16 proto)
{
	void *data, *data_end;
	__u8 protocol = 0;
	bool decrypted;
#ifdef ENABLE_IPV6
	struct ipv6hdr *ip6;
#endif
#ifdef ENABLE_IPV4
	struct iphdr *ip4;
#endif

	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6)) {
			ctx->mark = 0;
			return CTX_ACT_OK;
		}
		protocol = ip6->nexthdr;
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4)) {
			ctx->mark = 0;
			return CTX_ACT_OK;
		}
		protocol = ip4->protocol;
		break;
#endif
	default:
		return CTX_ACT_OK;
	}

	if (!decrypted) {
		/* Allow all non-ESP packets up the stack per normal case
		 * without encryption enabled.
		 */
		if (protocol != IPPROTO_ESP)
			return CTX_ACT_OK;
		/* Decrypt "key" is determined by SPI */
		ctx->mark = MARK_MAGIC_DECRYPT;
		/* We are going to pass this up the stack for IPsec decryption
		 * but eth_type_trans may already have labeled this as an
		 * OTHERHOST type packet. To avoid being dropped by IP stack
		 * before IPSec can be processed mark as a HOST packet.
		 */
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	}
	ctx->mark = 0;
#ifdef ENABLE_ENDPOINT_ROUTES
	return CTX_ACT_OK;
#else
	return ctx_redirect(ctx, CILIUM_IFINDEX, 0);
#endif /* ENABLE_ROUTING */
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 77,
  "endLine": 81,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/encrypt.h",
  "funcName": "do_decrypt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff  __maybe_unused *ctx",
    " __u16 __maybe_unused proto"
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
    "static __always_inline int do_decrypt (struct  __ctx_buff  __maybe_unused *ctx, __u16 __maybe_unused proto)\n",
    "{\n",
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
do_decrypt(struct __ctx_buff __maybe_unused *ctx, __u16 __maybe_unused proto)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_IPSEC */
#endif /* __LIB_ENCRYPT_H_ */

