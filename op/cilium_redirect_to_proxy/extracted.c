/* SPDX-License-Identifier: GPL-2.0 */
#define RECORD_FLOW_INFO
//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 16
#ifndef SKIP_SRV6_HANDLING//OPENED define SKIP_SRV6_HANDLING BEG
#define SKIP_SRV6_HANDLING
#endif //OPENED define SKIP_SRV6_HANDLING END

//OPENED COMMENT END : From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 16

//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 18
#ifndef EVENT_SOURCE//OPENED define EVENT_SOURCE BEG
#define EVENT_SOURCE LXC_ID
#endif //OPENED define EVENT_SOURCE END

//OPENED COMMENT END : From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 18

//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 42
#ifndef LB_SELECTION//OPENED define LB_SELECTION BEG
#define LB_SELECTION LB_SELECTION_RANDOM
#endif //OPENED define LB_SELECTION END

//OPENED COMMENT END : From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 42

//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 77
#ifndef HAVE_DIRECT_ACCESS_TO_MAP_VALUES//OPENED define HAVE_DIRECT_ACCESS_TO_MAP_VALUES BEG
#define HAVE_DIRECT_ACCESS_TO_MAP_VALUES \
    HAVE_PROG_TYPE_HELPER(sched_cls, bpf_fib_lookup)

#endif //OPENED define HAVE_DIRECT_ACCESS_TO_MAP_VALUES END

//OPENED COMMENT END: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 78

//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 80
#ifndef TAIL_CT_LOOKUP4(ID,//OPENED define TAIL_CT_LOOKUP4(ID, BEG
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

#endif //OPENED define TAIL_CT_LOOKUP4(ID, END

//OPENED COMMENT END: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 114

//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c startLine: 116
#ifndef TAIL_CT_LOOKUP6(ID,//OPENED define TAIL_CT_LOOKUP6(ID, BEG
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

#endif //OPENED define TAIL_CT_LOOKUP6(ID, END

//OPENED COMMENT END: From: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c endLine: 154

#include <bpf/ctx/skb.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#include <bpf/api.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#include <ep_config.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#include <node_config.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#include <bpf/verifier.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#include <linux/icmpv6.h>
//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef TAILCALL_H_OPENED_FRAMEWORK
#define TAILCALL_H_OPENED_FRAMEWORK
#include "lib/tailcall.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef COMMON_H_OPENED_FRAMEWORK
#define COMMON_H_OPENED_FRAMEWORK
#include "lib/common.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef CONFIG_H_OPENED_FRAMEWORK
#define CONFIG_H_OPENED_FRAMEWORK
#include "lib/config.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef MAPS_H_OPENED_FRAMEWORK
#define MAPS_H_OPENED_FRAMEWORK
#include "lib/maps.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef ARP_H_OPENED_FRAMEWORK
#define ARP_H_OPENED_FRAMEWORK
#include "lib/arp.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef EDT_H_OPENED_FRAMEWORK
#define EDT_H_OPENED_FRAMEWORK
#include "lib/edt.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef QM_H_OPENED_FRAMEWORK
#define QM_H_OPENED_FRAMEWORK
#include "lib/qm.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IPV6_H_OPENED_FRAMEWORK
#define IPV6_H_OPENED_FRAMEWORK
#include "lib/ipv6.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IPV4_H_OPENED_FRAMEWORK
#define IPV4_H_OPENED_FRAMEWORK
#include "lib/ipv4.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef ICMP6_H_OPENED_FRAMEWORK
#define ICMP6_H_OPENED_FRAMEWORK
#include "lib/icmp6.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef ETH_H_OPENED_FRAMEWORK
#define ETH_H_OPENED_FRAMEWORK
#include "lib/eth.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef DBG_H_OPENED_FRAMEWORK
#define DBG_H_OPENED_FRAMEWORK
#include "lib/dbg.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef L3_H_OPENED_FRAMEWORK
#define L3_H_OPENED_FRAMEWORK
#include "lib/l3.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef LXC_H_OPENED_FRAMEWORK
#define LXC_H_OPENED_FRAMEWORK
#include "lib/lxc.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IDENTITY_H_OPENED_FRAMEWORK
#define IDENTITY_H_OPENED_FRAMEWORK
#include "lib/identity.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef POLICY_H_OPENED_FRAMEWORK
#define POLICY_H_OPENED_FRAMEWORK
#include "lib/policy.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef LB_H_OPENED_FRAMEWORK
#define LB_H_OPENED_FRAMEWORK
#include "lib/lb.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef DROP_H_OPENED_FRAMEWORK
#define DROP_H_OPENED_FRAMEWORK
#include "lib/drop.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef TRACE_H_OPENED_FRAMEWORK
#define TRACE_H_OPENED_FRAMEWORK
#include "lib/trace.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef CSUM_H_OPENED_FRAMEWORK
#define CSUM_H_OPENED_FRAMEWORK
#include "lib/csum.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef EGRESS_POLICIES_H_OPENED_FRAMEWORK
#define EGRESS_POLICIES_H_OPENED_FRAMEWORK
#include "lib/egress_policies.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef ENCAP_H_OPENED_FRAMEWORK
#define ENCAP_H_OPENED_FRAMEWORK
#include "lib/encap.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef EPS_H_OPENED_FRAMEWORK
#define EPS_H_OPENED_FRAMEWORK
#include "lib/eps.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef NAT_H_OPENED_FRAMEWORK
#define NAT_H_OPENED_FRAMEWORK
#include "lib/nat.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef FIB_H_OPENED_FRAMEWORK
#define FIB_H_OPENED_FRAMEWORK
#include "lib/fib.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef NODEPORT_H_OPENED_FRAMEWORK
#define NODEPORT_H_OPENED_FRAMEWORK
#include "lib/nodeport.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef POLICY_LOG_H_OPENED_FRAMEWORK
#define POLICY_LOG_H_OPENED_FRAMEWORK
#include "lib/policy_log.h"
#endif 

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

/* Extracted from 
 /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c 
 startLine: 157 endLine: 162
 */ 
__section("xdp")
__always_inline bool
redirect_to_proxy(int verdict, enum ct_status status)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (status == CT_NEW || status == CT_ESTABLISHED ||  status == CT_REOPENED);
}
BPF_LICENSE("Dual BSD/GPL");
