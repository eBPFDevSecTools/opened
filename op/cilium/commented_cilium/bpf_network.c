// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#include "lib/common.h"
#include "lib/trace.h"
#include "lib/encrypt.h"

__section("from-network")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 15,
  "endLine": 88,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_network.c",
  "funcName": "from_network",
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
    "int from_network (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    __u16 proto __maybe_unused;\n",
    "    enum trace_reason reason = TRACE_REASON_UNKNOWN;\n",
    "    enum trace_point obs_point_to = TRACE_TO_STACK;\n",
    "    enum trace_point obs_point_from = TRACE_FROM_NETWORK;\n",
    "    bpf_clear_meta (ctx);\n",
    "    if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)\n",
    "        obs_point_from = TRACE_FROM_STACK;\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        goto out;\n",
    "    ret = do_decrypt (ctx, proto);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPSEC\n",
    "    if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)\n",
    "        reason = TRACE_REASON_ENCRYPTED;\n",
    "    if (ret == CTX_ACT_REDIRECT)\n",
    "        obs_point_to = TRACE_TO_HOST;\n",
    "\n",
    "#endif\n",
    "out :\n",
    "    send_trace_notify (ctx, obs_point_from, 0, 0, 0, ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);\n",
    "    send_trace_notify (ctx, obs_point_to, 0, 0, 0, ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);\n",
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
      "description": " Initialize the ctx buffer, passing protocols to the stack according to the imput packets (ESP packets coming from network; Non-ESP packets coming from network; Non-ESP packets coming from stack re-inserted by xfrm) ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
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
int from_network(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;

	__u16 proto __maybe_unused;
	enum trace_reason reason = TRACE_REASON_UNKNOWN;
	enum trace_point obs_point_to = TRACE_TO_STACK;
	enum trace_point obs_point_from = TRACE_FROM_NETWORK;

	bpf_clear_meta(ctx);

	/* This program should be attached to the tc-ingress of
	 * the network-facing device. Thus, as far as Cilium
	 * knows, no one touches to the ctx->mark before this
	 * program.
	 *
	 * One exception is the case the packets are re-insearted
	 * from the stack by xfrm. In that case, the packets should
	 * be marked with MARK_MAGIC_DECRYPT.
	 */
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)
		obs_point_from = TRACE_FROM_STACK;

#ifdef ENABLE_IPSEC
	/* Pass unknown protocols to the stack */
	if (!validate_ethertype(ctx, &proto))
		goto out;

	ret = do_decrypt(ctx, proto);
#endif

/* We need to handle following possible packets come to this program
 *
 * 1. ESP packets coming from network (encrypted and not marked)
 * 2. Non-ESP packets coming from network (plain and not marked)
 * 3. Non-ESP packets coming from stack re-inserted by xfrm (plain
 *    and marked with MARK_MAGIC_DECRYPT, IPSec mode only)
 *
 * 1. will be traced with TRACE_REASON_ENCRYPTED, because
 * do_decrypt marks them with MARK_MAGIC_DECRYPT.
 *
 * 2. will be traced without TRACE_REASON_ENCRYPTED, because
 * do_decrypt does't touch to mark.
 *
 * 3. will be traced without TRACE_REASON_ENCRYPTED, because
 * do_decrypt clears the mark.
 *
 * Note that 1. contains the ESP packets someone else generated.
 * In that case, we trace it as "encrypted", but it doesn't mean
 * "encrypted by Cilium".
 *
 * We won't use TRACE_REASON_ENCRYPTED even if the packets are ESP,
 * because it doesn't matter for the non-IPSec mode.
 */
#ifdef ENABLE_IPSEC
	if ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT)
		reason = TRACE_REASON_ENCRYPTED;

	/* Only possible redirect in here is the one in the do_decrypt
	 * which redirects to cilium_host.
	 */
	if (ret == CTX_ACT_REDIRECT)
		obs_point_to = TRACE_TO_HOST;
#endif

out:
	send_trace_notify(ctx, obs_point_from, 0, 0, 0,
			  ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);

	send_trace_notify(ctx, obs_point_to, 0, 0, 0,
			  ctx->ingress_ifindex, reason, TRACE_PAYLOAD_LEN);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
