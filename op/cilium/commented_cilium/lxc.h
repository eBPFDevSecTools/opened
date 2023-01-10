/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_LXC_H_
#define __LIB_LXC_H_

#include "common.h"
#include "utils.h"
#include "ipv6.h"
#include "ipv4.h"
#include "eth.h"
#include "dbg.h"
#include "trace.h"
#include "csum.h"
#include "l4.h"
#include "proxy.h"
#include "proxy_hairpin.h"

#define TEMPLATE_LXC_ID 0xffff

#ifndef DISABLE_SIP_VERIFICATION
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/lxc.h,
 Startline: 22,
 Endline: 34,
 Funcname: is_valid_lxc_src_ip,
 Input: (struct ipv6hdr * ip6 __maybe_unused),
 Output: static__always_inlineint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_IPV6
	union v6addr valid = {};

	BPF_V6(valid, LXC_IP);

	return !ipv6_addrcmp((union v6addr *) &ip6->saddr, &valid);
#else
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/lxc.h,
 Startline: 36,
 Endline: 45,
 Funcname: is_valid_lxc_src_ipv4,
 Input: (const struct iphdr * ip4 __maybe_unused),
 Output: static__always_inlineint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline
int is_valid_lxc_src_ipv4(const struct iphdr *ip4 __maybe_unused)
{
#ifdef ENABLE_IPV4
	return ip4->saddr == LXC_IPV4;
#else
	/* Can't send IPv4 if no IPv4 address is configured */
	return 0;
#endif
}
#else
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/lxc.h,
 Startline: 47,
 Endline: 51,
 Funcname: is_valid_lxc_src_ip,
 Input: (struct ipv6hdr * ip6 __maybe_unused),
 Output: static__always_inlineint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
	return 1;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/lxc.h,
 Startline: 53,
 Endline: 57,
 Funcname: is_valid_lxc_src_ipv4,
 Input: (struct iphdr * ip4 __maybe_unused),
 Output: static__always_inlineint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline
int is_valid_lxc_src_ipv4(struct iphdr *ip4 __maybe_unused)
{
	return 1;
}
#endif

#endif /* __LIB_LXC_H_ */
