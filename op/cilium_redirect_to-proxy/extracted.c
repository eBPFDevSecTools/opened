/* SPDX-License-Identifier: GPL-2.0 */
//OPENED COMMENT BEGIN: From: /home/palani/github/opened_extraction/examples/
#define SKIP_SRV6_HANDLING

#define EVENT_SOURCE LXC_ID

#define SEC(NAME) __attribute__((section(NAME), used))


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

//OPENED: included from: /home/palani/github/opened_exGtraction/examples/cilium/bpf_lxc.c

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

#define ENABLE_HOST_REDIRECT 1

//OPENED: included from: /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c

/* Extracted from 
 /home/palani/github/opened_extraction/examples/cilium/bpf_lxc.c 
 startLine: 157 endLine: 162
 */ 
SEC("xdp")
__always_inline bool redirect_to_proxy(int verdict, enum ct_status status)
{
	return is_defined(ENABLE_HOST_REDIRECT) && verdict > 0 &&
	       (status == CT_NEW || status == CT_ESTABLISHED ||  status == CT_REOPENED);
}
BPF_LICENSE("Dual BSD/GPL");
