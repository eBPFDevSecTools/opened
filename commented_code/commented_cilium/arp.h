/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ARP__
#define __LIB_ARP__

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "eth.h"
#include "dbg.h"
#include "drop.h"

struct arp_eth {
	unsigned char		ar_sha[ETH_ALEN];
	__be32                  ar_sip;
	unsigned char		ar_tha[ETH_ALEN];
	__be32                  ar_tip;
} __packed;

/* Check if packet is ARP request for IP */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 30,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/arp.h",
  "funcName": "arp_check",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ethhdr *eth",
    " const struct arphdr *arp",
    " union macaddr *mac"
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
    "static __always_inline int arp_check (struct ethhdr *eth, const struct arphdr *arp, union macaddr *mac)\n",
    "{\n",
    "    union macaddr *dmac = (union macaddr *) &eth->h_dest;\n",
    "    return arp->ar_op == bpf_htons (ARPOP_REQUEST) && arp->ar_hrd == bpf_htons (ARPHRD_ETHER) && (eth_is_bcast (dmac) || !eth_addrcmp (dmac, mac));\n",
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
static __always_inline int arp_check(struct ethhdr *eth,
				     const struct arphdr *arp,
				     union macaddr *mac)
{
	union macaddr *dmac = (union macaddr *) &eth->h_dest;

	return arp->ar_op  == bpf_htons(ARPOP_REQUEST) &&
	       arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
	       (eth_is_bcast(dmac) || !eth_addrcmp(dmac, mac));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 32,
  "endLine": 49,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/arp.h",
  "funcName": "arp_prepare_response",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " union macaddr *smac",
    " __be32 sip",
    " union macaddr *dmac",
    " __be32 tip"
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
    "static __always_inline int arp_prepare_response (struct  __ctx_buff *ctx, union macaddr *smac, __be32 sip, union macaddr *dmac, __be32 tip)\n",
    "{\n",
    "    __be16 arpop = bpf_htons (ARPOP_REPLY);\n",
    "    if (eth_store_saddr (ctx, smac->addr, 0) < 0 || eth_store_daddr (ctx, dmac->addr, 0) < 0 || ctx_store_bytes (ctx, 20, &arpop, sizeof (arpop), 0) < 0 || ctx_store_bytes (ctx, 22, smac, ETH_ALEN, 0) < 0 || ctx_store_bytes (ctx, 28, &sip, sizeof (sip), 0) < 0 || ctx_store_bytes (ctx, 32, dmac, ETH_ALEN, 0) < 0 || ctx_store_bytes (ctx, 38, &tip, sizeof (tip), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
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
static __always_inline int
arp_prepare_response(struct __ctx_buff *ctx, union macaddr *smac, __be32 sip,
		     union macaddr *dmac, __be32 tip)
{
	__be16 arpop = bpf_htons(ARPOP_REPLY);

	if (eth_store_saddr(ctx, smac->addr, 0) < 0 ||
	    eth_store_daddr(ctx, dmac->addr, 0) < 0 ||
	    ctx_store_bytes(ctx, 20, &arpop, sizeof(arpop), 0) < 0 ||
	    /* sizeof(macadrr)=8 because of padding, use ETH_ALEN instead */
	    ctx_store_bytes(ctx, 22, smac, ETH_ALEN, 0) < 0 ||
	    ctx_store_bytes(ctx, 28, &sip, sizeof(sip), 0) < 0 ||
	    ctx_store_bytes(ctx, 32, dmac, ETH_ALEN, 0) < 0 ||
	    ctx_store_bytes(ctx, 38, &tip, sizeof(tip), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 51,
  "endLine": 73,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/arp.h",
  "funcName": "arp_validate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx",
    " union macaddr *mac",
    " union macaddr *smac",
    " __be32 *sip",
    " __be32 *tip"
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
    "static __always_inline bool arp_validate (const struct  __ctx_buff *ctx, union macaddr *mac, union macaddr *smac, __be32 *sip, __be32 *tip)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct arphdr *arp = data + ETH_HLEN;\n",
    "    struct ethhdr *eth = data;\n",
    "    struct arp_eth *arp_eth;\n",
    "    if (data + ETH_HLEN + sizeof (*arp) + sizeof (*arp_eth) > data_end)\n",
    "        return false;\n",
    "    if (!arp_check (eth, arp, mac))\n",
    "        return false;\n",
    "    arp_eth = data + ETH_HLEN + sizeof (*arp);\n",
    "    *smac = *(unionmacaddr*) &eth->h_source;\n",
    "    *sip = arp_eth->ar_sip;\n",
    "    *tip = arp_eth->ar_tip;\n",
    "    return true;\n",
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
static __always_inline bool
arp_validate(const struct __ctx_buff *ctx, union macaddr *mac,
	     union macaddr *smac, __be32 *sip, __be32 *tip)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct arphdr *arp = data + ETH_HLEN;
	struct ethhdr *eth = data;
	struct arp_eth *arp_eth;

	if (data + ETH_HLEN + sizeof(*arp) + sizeof(*arp_eth) > data_end)
		return false;

	if (!arp_check(eth, arp, mac))
		return false;

	arp_eth = data + ETH_HLEN + sizeof(*arp);
	*smac = *(union macaddr *) &eth->h_source;
	*sip = arp_eth->ar_sip;
	*tip = arp_eth->ar_tip;

	return true;
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
          "\treturn ctx_ctx",
          " ctx_get_ifindexctx",
          " direction"
        ]
      }
    ]
  },
  "startLine": 75,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/arp.h",
  "funcName": "arp_respond",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " union macaddr *smac",
    " __be32 sip",
    " union macaddr *dmac",
    " __be32 tip",
    " int direction"
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
    "static __always_inline int arp_respond (struct  __ctx_buff *ctx, union macaddr *smac, __be32 sip, union macaddr *dmac, __be32 tip, int direction)\n",
    "{\n",
    "    int ret = arp_prepare_response (ctx, smac, sip, dmac, tip);\n",
    "    if (unlikely (ret != 0))\n",
    "        goto error;\n",
    "    cilium_dbg_capture (ctx, DBG_CAPTURE_DELIVERY, ctx_get_ifindex (ctx));\n",
    "    return ctx_redirect (ctx, ctx_get_ifindex (ctx), direction);\n",
    "error :\n",
    "    return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
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
arp_respond(struct __ctx_buff *ctx, union macaddr *smac, __be32 sip,
	    union macaddr *dmac, __be32 tip, int direction)
{
	int ret = arp_prepare_response(ctx, smac, sip, dmac, tip);

	if (unlikely(ret != 0))
		goto error;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY,
			   ctx_get_ifindex(ctx));
	return ctx_redirect(ctx, ctx_get_ifindex(ctx), direction);

error:
	return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
}


#endif /* __LIB_ARP__ */