/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_FIB_H_
#define __LIB_FIB_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "common.h"
#include "l3.h"

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
    },
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
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 66,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/fib.h",
  "funcName": "redirect_direct_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " int l3_off __maybe_unused",
    " struct ipv6hdr * ip6 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "bpf_fib_lookup",
    "redirect",
    "fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int redirect_direct_v6 (struct  __ctx_buff * ctx __maybe_unused, int l3_off __maybe_unused, struct ipv6hdr * ip6 __maybe_unused)\n",
    "{\n",
    "    bool no_neigh = is_defined (ENABLE_SKIP_FIB);\n",
    "    int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;\n",
    "    struct bpf_redir_neigh *nh = NULL;\n",
    "\n",
    "# ifndef ENABLE_SKIP_FIB\n",
    "    struct bpf_redir_neigh nh_params;\n",
    "    struct bpf_fib_lookup fib_params = {\n",
    "        .family = AF_INET6,\n",
    "        .ifindex = ctx->ingress_ifindex,}\n",
    "    ;\n",
    "    ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_src, (union v6addr *) &ip6->saddr);\n",
    "    ipv6_addr_copy ((union v6addr *) &fib_params.ipv6_dst, (union v6addr *) &ip6->daddr);\n",
    "    ret = fib_lookup (ctx, & fib_params, sizeof (fib_params), BPF_FIB_LOOKUP_DIRECT);\n",
    "    switch (ret) {\n",
    "    case BPF_FIB_LKUP_RET_SUCCESS :\n",
    "        break;\n",
    "    case BPF_FIB_LKUP_RET_NO_NEIGH :\n",
    "        nh_params.nh_family = fib_params.family;\n",
    "        __bpf_memcpy_builtin (&nh_params.ipv6_nh, &fib_params.ipv6_dst, sizeof (nh_params.ipv6_nh));\n",
    "        no_neigh = true;\n",
    "        nh = &nh_params;\n",
    "        break;\n",
    "    default :\n",
    "        return CTX_ACT_DROP;\n",
    "    }\n",
    "    oif = fib_params.ifindex;\n",
    "\n",
    "# endif /* ENABLE_SKIP_FIB */\n",
    "    ret = ipv6_l3 (ctx, l3_off, NULL, NULL, METRIC_EGRESS);\n",
    "    if (unlikely (ret != CTX_ACT_OK))\n",
    "        return ret;\n",
    "    if (no_neigh)\n",
    "        return redirect_neigh (oif, nh, nh ? sizeof (*nh) : 0, 0);\n",
    "\n",
    "# ifndef ENABLE_SKIP_FIB\n",
    "    if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "        return CTX_ACT_DROP;\n",
    "    if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "        return CTX_ACT_DROP;\n",
    "    return ctx_redirect (ctx, oif, 0);\n",
    "\n",
    "# endif /* ENABLE_SKIP_FIB */\n",
    "    return CTX_ACT_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "unlikely",
    "ctx_redirect",
    "is_defined",
    "__bpf_memcpy_builtin",
    "redirect_neigh",
    "ipv6_addr_copy",
    "eth_store_saddr",
    "eth_store_daddr",
    "ipv6_l3"
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
redirect_direct_v6(struct __ctx_buff *ctx __maybe_unused,
		   int l3_off __maybe_unused,
		   struct ipv6hdr *ip6 __maybe_unused)
{
	bool no_neigh = is_defined(ENABLE_SKIP_FIB);
	int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;
	struct bpf_redir_neigh *nh = NULL;
# ifndef ENABLE_SKIP_FIB
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET6,
		.ifindex	= ctx->ingress_ifindex,
	};

	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_src,
		       (union v6addr *)&ip6->saddr);
	ipv6_addr_copy((union v6addr *)&fib_params.ipv6_dst,
		       (union v6addr *)&ip6->daddr);

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		nh_params.nh_family = fib_params.family;
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, &fib_params.ipv6_dst,
				     sizeof(nh_params.ipv6_nh));
		no_neigh = true;
		nh = &nh_params;
		break;
	default:
		return CTX_ACT_DROP;
	}

	oif = fib_params.ifindex;
# endif /* ENABLE_SKIP_FIB */

	ret = ipv6_l3(ctx, l3_off, NULL, NULL, METRIC_EGRESS);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (no_neigh)
		return redirect_neigh(oif, nh, nh ? sizeof(*nh) : 0, 0);
# ifndef ENABLE_SKIP_FIB
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return CTX_ACT_DROP;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return CTX_ACT_DROP;
	return ctx_redirect(ctx, oif, 0);
# endif /* ENABLE_SKIP_FIB */
	return CTX_ACT_DROP;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
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
  "startLine": 70,
  "endLine": 126,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/fib.h",
  "funcName": "redirect_direct_v4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " int l3_off __maybe_unused",
    " struct iphdr * ip4 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "bpf_fib_lookup",
    "redirect",
    "fib_lookup"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int redirect_direct_v4 (struct  __ctx_buff * ctx __maybe_unused, int l3_off __maybe_unused, struct iphdr * ip4 __maybe_unused)\n",
    "{\n",
    "    bool no_neigh = is_defined (ENABLE_SKIP_FIB);\n",
    "    int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;\n",
    "    struct bpf_redir_neigh *nh = NULL;\n",
    "\n",
    "# ifndef ENABLE_SKIP_FIB\n",
    "    struct bpf_redir_neigh nh_params;\n",
    "    struct bpf_fib_lookup fib_params = {\n",
    "        .family = AF_INET,\n",
    "        .ifindex = ctx->ingress_ifindex,\n",
    "        .ipv4_src = ip4->saddr,\n",
    "        .ipv4_dst = ip4->daddr,}\n",
    "    ;\n",
    "    ret = fib_lookup (ctx, & fib_params, sizeof (fib_params), BPF_FIB_LOOKUP_DIRECT);\n",
    "    switch (ret) {\n",
    "    case BPF_FIB_LKUP_RET_SUCCESS :\n",
    "        break;\n",
    "    case BPF_FIB_LKUP_RET_NO_NEIGH :\n",
    "        nh_params.nh_family = fib_params.family;\n",
    "        __bpf_memcpy_builtin (&nh_params.ipv6_nh, &fib_params.ipv6_dst, sizeof (nh_params.ipv6_nh));\n",
    "        no_neigh = true;\n",
    "        nh = &nh_params;\n",
    "        break;\n",
    "    default :\n",
    "        return CTX_ACT_DROP;\n",
    "    }\n",
    "    oif = fib_params.ifindex;\n",
    "\n",
    "# endif /* ENABLE_SKIP_FIB */\n",
    "    ret = ipv4_l3 (ctx, l3_off, NULL, NULL, ip4);\n",
    "    if (unlikely (ret != CTX_ACT_OK))\n",
    "        return ret;\n",
    "    if (no_neigh)\n",
    "        return redirect_neigh (oif, nh, nh ? sizeof (*nh) : 0, 0);\n",
    "\n",
    "# ifndef ENABLE_SKIP_FIB\n",
    "    if (eth_store_daddr (ctx, fib_params.dmac, 0) < 0)\n",
    "        return CTX_ACT_DROP;\n",
    "    if (eth_store_saddr (ctx, fib_params.smac, 0) < 0)\n",
    "        return CTX_ACT_DROP;\n",
    "    return ctx_redirect (ctx, oif, 0);\n",
    "\n",
    "# endif /* ENABLE_SKIP_FIB */\n",
    "    return CTX_ACT_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "unlikely",
    "ctx_redirect",
    "is_defined",
    "__bpf_memcpy_builtin",
    "redirect_neigh",
    "ipv4_l3",
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
static __always_inline int
redirect_direct_v4(struct __ctx_buff *ctx __maybe_unused,
		   int l3_off __maybe_unused,
		   struct iphdr *ip4 __maybe_unused)
{
	/* For deployments with just single external dev, redirect_neigh()
	 * will resolve the GW and do L2 resolution for us. For multi-device
	 * deployments we perform a FIB lookup prior to the redirect. If the
	 * neigh entry cannot be resolved, we ask redirect_neigh() to do it,
	 * otherwise we can directly call redirect().
	 */
	bool no_neigh = is_defined(ENABLE_SKIP_FIB);
	int ret, oif = DIRECT_ROUTING_DEV_IFINDEX;
	struct bpf_redir_neigh *nh = NULL;
# ifndef ENABLE_SKIP_FIB
	struct bpf_redir_neigh nh_params;
	struct bpf_fib_lookup fib_params = {
		.family		= AF_INET,
		.ifindex	= ctx->ingress_ifindex,
		.ipv4_src	= ip4->saddr,
		.ipv4_dst	= ip4->daddr,
	};

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params),
			 BPF_FIB_LOOKUP_DIRECT);
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		/* GW could also be v6, so copy union. */
		nh_params.nh_family = fib_params.family;
		__bpf_memcpy_builtin(&nh_params.ipv6_nh, &fib_params.ipv6_dst,
				     sizeof(nh_params.ipv6_nh));
		no_neigh = true;
		nh = &nh_params;
		break;
	default:
		return CTX_ACT_DROP;
	}

	oif = fib_params.ifindex;
# endif /* ENABLE_SKIP_FIB */

	ret = ipv4_l3(ctx, l3_off, NULL, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	if (no_neigh)
		return redirect_neigh(oif, nh, nh ? sizeof(*nh) : 0, 0);
# ifndef ENABLE_SKIP_FIB
	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return CTX_ACT_DROP;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return CTX_ACT_DROP;
	return ctx_redirect(ctx, oif, 0);
# endif /* ENABLE_SKIP_FIB */
	return CTX_ACT_DROP;
}
#endif /* ENABLE_IPV4 */

#endif /* __LIB_FIB_H_ */
