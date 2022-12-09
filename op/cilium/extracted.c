/* SPDX-License-Identifier: GPL-2.0 */
#define RECORD_FLOW_INFO
//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c startLine: 10
#ifndef SKIP_POLICY_MAP//OPENED define SKIP_POLICY_MAP BEG
#define SKIP_POLICY_MAP	1
#endif //OPENED define SKIP_POLICY_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c endLine: 10

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c startLine: 11
#ifndef SKIP_CALLS_MAP//OPENED define SKIP_CALLS_MAP BEG
#define SKIP_CALLS_MAP	1
#endif //OPENED define SKIP_CALLS_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c endLine: 11

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c startLine: 20
#ifndef SYS_REJECT//OPENED define SYS_REJECT BEG
#define SYS_REJECT	0
#endif //OPENED define SYS_REJECT END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c endLine: 20

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c startLine: 21
#ifndef SYS_PROCEED//OPENED define SYS_PROCEED BEG
#define SYS_PROCEED	1
#endif //OPENED define SYS_PROCEED END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c endLine: 21

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c startLine: 11
#ifndef SKIP_CALLS_MAP//OPENED define SKIP_CALLS_MAP BEG
#define SKIP_CALLS_MAP 1
#endif //OPENED define SKIP_CALLS_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c endLine: 11

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c startLine: 12
#ifndef SKIP_POLICY_MAP//OPENED define SKIP_POLICY_MAP BEG
#define SKIP_POLICY_MAP 1
#endif //OPENED define SKIP_POLICY_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c endLine: 12

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c startLine: 14
#ifndef SOCKMAP//OPENED define SOCKMAP BEG
#define SOCKMAP 1
#endif //OPENED define SOCKMAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c endLine: 14

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c startLine: 4
#ifndef _GNU_SOURCE//OPENED define _GNU_SOURCE BEG
#define _GNU_SOURCE
#endif //OPENED define _GNU_SOURCE END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c endLine: 4

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c startLine: 18
#ifndef __non_bpf_context//OPENED define __non_bpf_context BEG
//#define __non_bpf_context	1
#endif //OPENED define __non_bpf_context END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c endLine: 18

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c startLine: 28
#ifndef abs(x)//OPENED define abs(x) BEG
#define abs(x)	({ x < 0 ? -x : x; })
#endif //OPENED define abs(x) END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c endLine: 28

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c startLine: 142
#ifndef KERNEL_HZ//OPENED define KERNEL_HZ BEG
//printf("#define KERNEL_HZ %lu\t/* warp: %lu jiffies */\n", fixed->jiffies[0], warp);
#endif //OPENED define KERNEL_HZ END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/cilium-probe-kernel-hz.c endLine: 142

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c startLine: 10
#ifndef IS_BPF_OVERLAY//OPENED define IS_BPF_OVERLAY BEG
#define IS_BPF_OVERLAY 1
#endif //OPENED define IS_BPF_OVERLAY END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c endLine: 10

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c startLine: 15
#ifndef SKIP_ICMPV6_NS_HANDLING//OPENED define SKIP_ICMPV6_NS_HANDLING BEG
#define SKIP_ICMPV6_NS_HANDLING
#endif //OPENED define SKIP_ICMPV6_NS_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c endLine: 15

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c startLine: 20
#ifndef SKIP_ICMPV6_ECHO_HANDLING//OPENED define SKIP_ICMPV6_ECHO_HANDLING BEG
#define SKIP_ICMPV6_ECHO_HANDLING
#endif //OPENED define SKIP_ICMPV6_ECHO_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c endLine: 20

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c startLine: 24
#ifndef SKIP_SRV6_HANDLING//OPENED define SKIP_SRV6_HANDLING BEG
#define SKIP_SRV6_HANDLING
#endif //OPENED define SKIP_SRV6_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_overlay.c endLine: 24

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 10
#ifndef IS_BPF_HOST//OPENED define IS_BPF_HOST BEG
#define IS_BPF_HOST 1
#endif //OPENED define IS_BPF_HOST END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 10

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 12
#ifndef EVENT_SOURCE//OPENED define EVENT_SOURCE BEG
#define EVENT_SOURCE HOST_EP_ID
#endif //OPENED define EVENT_SOURCE END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 12

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 17
#ifndef TEMPLATE_HOST_EP_ID//OPENED define TEMPLATE_HOST_EP_ID BEG
#define TEMPLATE_HOST_EP_ID 0xffff
#endif //OPENED define TEMPLATE_HOST_EP_ID END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 17

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 23
#ifndef ACTION_UNKNOWN_ICMP6_NS//OPENED define ACTION_UNKNOWN_ICMP6_NS BEG
#define ACTION_UNKNOWN_ICMP6_NS CTX_ACT_OK
#endif //OPENED define ACTION_UNKNOWN_ICMP6_NS END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 23

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 26
#ifndef ENCRYPT_OR_PROXY_MAGIC//OPENED define ENCRYPT_OR_PROXY_MAGIC BEG
#define ENCRYPT_OR_PROXY_MAGIC 0
#endif //OPENED define ENCRYPT_OR_PROXY_MAGIC END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 26

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 31
#ifndef SKIP_ICMPV6_ECHO_HANDLING//OPENED define SKIP_ICMPV6_ECHO_HANDLING BEG
#define SKIP_ICMPV6_ECHO_HANDLING
#endif //OPENED define SKIP_ICMPV6_ECHO_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 31

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c startLine: 84
#ifndef SECCTX_FROM_IPCACHE_OK//OPENED define SECCTX_FROM_IPCACHE_OK BEG
#define SECCTX_FROM_IPCACHE_OK	2
#endif //OPENED define SECCTX_FROM_IPCACHE_OK END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c endLine: 84

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c startLine: 11
#ifndef SKIP_CALLS_MAP//OPENED define SKIP_CALLS_MAP BEG
#define SKIP_CALLS_MAP 1
#endif //OPENED define SKIP_CALLS_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c endLine: 11

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c startLine: 12
#ifndef SKIP_POLICY_MAP//OPENED define SKIP_POLICY_MAP BEG
#define SKIP_POLICY_MAP 1
#endif //OPENED define SKIP_POLICY_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c endLine: 12

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c startLine: 14
#ifndef SOCKMAP//OPENED define SOCKMAP BEG
#define SOCKMAP 1
#endif //OPENED define SOCKMAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c endLine: 14

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c startLine: 11
#ifndef SKIP_POLICY_MAP//OPENED define SKIP_POLICY_MAP BEG
#define SKIP_POLICY_MAP 1
#endif //OPENED define SKIP_POLICY_MAP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c endLine: 11

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c startLine: 16
#ifndef SKIP_ICMPV6_NS_HANDLING//OPENED define SKIP_ICMPV6_NS_HANDLING BEG
#define SKIP_ICMPV6_NS_HANDLING
#endif //OPENED define SKIP_ICMPV6_NS_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c endLine: 16

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c startLine: 22
#ifndef SKIP_ICMPV6_HOPLIMIT_HANDLING//OPENED define SKIP_ICMPV6_HOPLIMIT_HANDLING BEG
#define SKIP_ICMPV6_HOPLIMIT_HANDLING
#endif //OPENED define SKIP_ICMPV6_HOPLIMIT_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c endLine: 22

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c startLine: 27
#ifndef SKIP_ICMPV6_ECHO_HANDLING//OPENED define SKIP_ICMPV6_ECHO_HANDLING BEG
#define SKIP_ICMPV6_ECHO_HANDLING
#endif //OPENED define SKIP_ICMPV6_ECHO_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c endLine: 27

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c startLine: 31
#ifndef SKIP_SRV6_HANDLING//OPENED define SKIP_SRV6_HANDLING BEG
#define SKIP_SRV6_HANDLING
#endif //OPENED define SKIP_SRV6_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c endLine: 31

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 5
#ifndef DEBUG//OPENED define DEBUG BEG
#define DEBUG
#endif //OPENED define DEBUG END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 5

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 6
#ifndef TRACE_NOTIFY//OPENED define TRACE_NOTIFY BEG
#define TRACE_NOTIFY
#endif //OPENED define TRACE_NOTIFY END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 6

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 7
#ifndef DROP_NOTIFY//OPENED define DROP_NOTIFY BEG
#define DROP_NOTIFY
#endif //OPENED define DROP_NOTIFY END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 7

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 8
#ifndef POLICY_VERDICT_NOTIFY//OPENED define POLICY_VERDICT_NOTIFY BEG
#define POLICY_VERDICT_NOTIFY
#endif //OPENED define POLICY_VERDICT_NOTIFY END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 8

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 9
#ifndef ENABLE_VTEP//OPENED define ENABLE_VTEP BEG
#define ENABLE_VTEP
#endif //OPENED define ENABLE_VTEP END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 9

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 10
#ifndef ENABLE_CAPTURE//OPENED define ENABLE_CAPTURE BEG
#define ENABLE_CAPTURE
#endif //OPENED define ENABLE_CAPTURE END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 10

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 21
#ifndef SKIP_UNDEF_LPM_LOOKUP_FN//OPENED define SKIP_UNDEF_LPM_LOOKUP_FN BEG
#define SKIP_UNDEF_LPM_LOOKUP_FN
#endif //OPENED define SKIP_UNDEF_LPM_LOOKUP_FN END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 21

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c startLine: 35
#ifndef DECLARE(type)//OPENED define DECLARE(type) BEG
#define DECLARE(type)			\
{					\
	type s = {};			\
	trace_printk("%p", 1, &s);	\
}

#endif //OPENED define DECLARE(type) END

//OPENED COMMENT END: From: /home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c endLine: 39

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 16
#ifndef SKIP_SRV6_HANDLING//OPENED define SKIP_SRV6_HANDLING BEG
#define SKIP_SRV6_HANDLING
#endif //OPENED define SKIP_SRV6_HANDLING END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 16

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 18
#ifndef EVENT_SOURCE//OPENED define EVENT_SOURCE BEG
#define EVENT_SOURCE LXC_ID
#endif //OPENED define EVENT_SOURCE END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 18

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 42
#ifndef LB_SELECTION//OPENED define LB_SELECTION BEG
#define LB_SELECTION LB_SELECTION_RANDOM
#endif //OPENED define LB_SELECTION END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 42

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 77
#ifndef HAVE_DIRECT_ACCESS_TO_MAP_VALUES//OPENED define HAVE_DIRECT_ACCESS_TO_MAP_VALUES BEG
#define HAVE_DIRECT_ACCESS_TO_MAP_VALUES \
    HAVE_PROG_TYPE_HELPER(sched_cls, bpf_fib_lookup)

#endif //OPENED define HAVE_DIRECT_ACCESS_TO_MAP_VALUES END

//OPENED COMMENT END: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 78

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 80
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

//OPENED COMMENT END: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 114

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c startLine: 116
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

//OPENED COMMENT END: From: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c endLine: 154

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c startLine: 9
#ifndef TO_STRING(X)//OPENED define TO_STRING(X) BEG
#define TO_STRING(X) #X
#endif //OPENED define TO_STRING(X) END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c endLine: 9

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c startLine: 10
#ifndef STRINGIFY(X)//OPENED define STRINGIFY(X) BEG
#define STRINGIFY(X) TO_STRING(X)
#endif //OPENED define STRINGIFY(X) END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c endLine: 10

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c startLine: 21
#ifndef BPF_CUSTOM_PROG_FILE//OPENED define BPF_CUSTOM_PROG_FILE BEG
#define BPF_CUSTOM_PROG_FILE bytecount.h
#endif //OPENED define BPF_CUSTOM_PROG_FILE END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c endLine: 21

//OPENED COMMENT BEGIN: From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c startLine: 26
#ifndef BPF_CUSTOM_PROG_NAME//OPENED define BPF_CUSTOM_PROG_NAME BEG
#define BPF_CUSTOM_PROG_NAME custom
#endif //OPENED define BPF_CUSTOM_PROG_NAME END

//OPENED COMMENT END : From: /home/sayandes/opened_extraction/examples/cilium/custom/bpf_custom.c endLine: 26

#include <bpf/ctx/skb.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#include <bpf/api.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#include <ep_config.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#include <node_config.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#include <bpf/verifier.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#include <linux/icmpv6.h>
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef TAILCALL_H_OPENED_FRAMEWORK
#define TAILCALL_H_OPENED_FRAMEWORK
#include "lib/tailcall.h"
<<<<<<< HEAD
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef COMMON_H_OPENED_FRAMEWORK
#define COMMON_H_OPENED_FRAMEWORK
#include "lib/common.h"
#endif 

=======
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef COMMON_H_OPENED_FRAMEWORK
#define COMMON_H_OPENED_FRAMEWORK
#include "lib/common.h"
#endif 

>>>>>>> main
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef CONFIG_H_OPENED_FRAMEWORK
#define CONFIG_H_OPENED_FRAMEWORK
#include "lib/config.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef MAPS_H_OPENED_FRAMEWORK
#define MAPS_H_OPENED_FRAMEWORK
#include "lib/maps.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef ARP_H_OPENED_FRAMEWORK
#define ARP_H_OPENED_FRAMEWORK
#include "lib/arp.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef EDT_H_OPENED_FRAMEWORK
#define EDT_H_OPENED_FRAMEWORK
#include "lib/edt.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef QM_H_OPENED_FRAMEWORK
#define QM_H_OPENED_FRAMEWORK
#include "lib/qm.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IPV6_H_OPENED_FRAMEWORK
#define IPV6_H_OPENED_FRAMEWORK
#include "lib/ipv6.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef IPV4_H_OPENED_FRAMEWORK
#define IPV4_H_OPENED_FRAMEWORK
#include "lib/ipv4.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef ICMP6_H_OPENED_FRAMEWORK
#define ICMP6_H_OPENED_FRAMEWORK
#include "lib/icmp6.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef ETH_H_OPENED_FRAMEWORK
#define ETH_H_OPENED_FRAMEWORK
#include "lib/eth.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef DBG_H_OPENED_FRAMEWORK
#define DBG_H_OPENED_FRAMEWORK
#include "lib/dbg.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef L3_H_OPENED_FRAMEWORK
#define L3_H_OPENED_FRAMEWORK
#include "lib/l3.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef LXC_H_OPENED_FRAMEWORK
#define LXC_H_OPENED_FRAMEWORK
#include "lib/lxc.h"
<<<<<<< HEAD
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IDENTITY_H_OPENED_FRAMEWORK
#define IDENTITY_H_OPENED_FRAMEWORK
#include "lib/identity.h"
#endif 

=======
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef IDENTITY_H_OPENED_FRAMEWORK
#define IDENTITY_H_OPENED_FRAMEWORK
#include "lib/identity.h"
#endif 

>>>>>>> main
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef POLICY_H_OPENED_FRAMEWORK
#define POLICY_H_OPENED_FRAMEWORK
#include "lib/policy.h"
<<<<<<< HEAD
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef LB_H_OPENED_FRAMEWORK
#define LB_H_OPENED_FRAMEWORK
#include "lib/lb.h"
#endif 

=======
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef LB_H_OPENED_FRAMEWORK
#define LB_H_OPENED_FRAMEWORK
#include "lib/lb.h"
#endif 

>>>>>>> main
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef DROP_H_OPENED_FRAMEWORK
#define DROP_H_OPENED_FRAMEWORK
#include "lib/drop.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef TRACE_H_OPENED_FRAMEWORK
#define TRACE_H_OPENED_FRAMEWORK
#include "lib/trace.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef CSUM_H_OPENED_FRAMEWORK
#define CSUM_H_OPENED_FRAMEWORK
#include "lib/csum.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef EGRESS_POLICIES_H_OPENED_FRAMEWORK
#define EGRESS_POLICIES_H_OPENED_FRAMEWORK
#include "lib/egress_policies.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef ENCAP_H_OPENED_FRAMEWORK
#define ENCAP_H_OPENED_FRAMEWORK
#include "lib/encap.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef EPS_H_OPENED_FRAMEWORK
#define EPS_H_OPENED_FRAMEWORK
#include "lib/eps.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef NAT_H_OPENED_FRAMEWORK
#define NAT_H_OPENED_FRAMEWORK
#include "lib/nat.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef FIB_H_OPENED_FRAMEWORK
#define FIB_H_OPENED_FRAMEWORK
#include "lib/fib.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef NODEPORT_H_OPENED_FRAMEWORK
#define NODEPORT_H_OPENED_FRAMEWORK
#include "lib/nodeport.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef POLICY_LOG_H_OPENED_FRAMEWORK
#define POLICY_LOG_H_OPENED_FRAMEWORK
#include "lib/policy_log.h"
<<<<<<< HEAD
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef PROXY_H_OPENED_FRAMEWORK
#define PROXY_H_OPENED_FRAMEWORK
#include "lib/proxy.h"
#endif 

=======
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_lxc.c

#ifndef PROXY_H_OPENED_FRAMEWORK
#define PROXY_H_OPENED_FRAMEWORK
#include "lib/proxy.h"
#endif 

>>>>>>> main
//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef L4_H_OPENED_FRAMEWORK
#define L4_H_OPENED_FRAMEWORK
#include "lib/l4.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef HOST_FIREWALL_H_OPENED_FRAMEWORK
#define HOST_FIREWALL_H_OPENED_FRAMEWORK
#include "lib/host_firewall.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef OVERLOADABLE_H_OPENED_FRAMEWORK
#define OVERLOADABLE_H_OPENED_FRAMEWORK
#include "lib/overloadable.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

#ifndef ENCRYPT_H_OPENED_FRAMEWORK
#define ENCRYPT_H_OPENED_FRAMEWORK
#include "lib/encrypt.h"
#endif 

//OPENED: included from: /home/sayandes/opened_extraction/examples/cilium/bpf_host.c

<<<<<<< HEAD
=======
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_host.c 
 startLine: 67 endLine: 82
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
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_host.c 
 startLine: 471 endLine: 671
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
>>>>>>> main
BPF_LICENSE("Dual BSD/GPL");
