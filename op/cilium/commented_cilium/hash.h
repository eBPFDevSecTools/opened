/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __HASH_H_
#define __HASH_H_

#include "common.h"
#include "jhash.h"

/* The daddr is explicitly excluded from the hash here in order to allow for
 * backend selection to choose the same backend even on different service VIPs.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 13,
  "endLine": 18,
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/hash.h",
  "funcName": "hash_from_tuple_v4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *tuple"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "xdp",
    "lwt_xmit",
    "tracepoint",
    "cgroup_device",
    "lwt_seg6local",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sched_act",
    "flow_dissector",
    "sk_msg",
    "cgroup_sock_addr",
    "lwt_out",
    "cgroup_sock",
    "sk_reuseport",
    "lwt_in",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "sched_cls"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static __always_inline __u32 hash_from_tuple_v4(const struct ipv4_ct_tuple *tuple)
{
	return jhash_3words(tuple->saddr,
			    ((__u32)tuple->dport << 16) | tuple->sport,
			    tuple->nexthdr, HASH_INIT4_SEED);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 20,
  "endLine": 35,
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/hash.h",
  "funcName": "hash_from_tuple_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6_ct_tuple *tuple"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "xdp",
    "lwt_xmit",
    "tracepoint",
    "cgroup_device",
    "lwt_seg6local",
    "sock_ops",
    "raw_tracepoint",
    "socket_filter",
    "sched_act",
    "flow_dissector",
    "sk_msg",
    "cgroup_sock_addr",
    "lwt_out",
    "cgroup_sock",
    "sk_reuseport",
    "lwt_in",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "sched_cls"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static __always_inline __u32 hash_from_tuple_v6(const struct ipv6_ct_tuple *tuple)
{
	__u32 a, b, c;

	a = tuple->saddr.p1;
	b = tuple->saddr.p2;
	c = tuple->saddr.p3;
	__jhash_mix(a, b, c);
	a += tuple->saddr.p4;
	b += ((__u32)tuple->dport << 16) | tuple->sport;
	c += tuple->nexthdr;
	__jhash_mix(a, b, c);
	a += HASH_INIT6_SEED;
	__jhash_final(a, b, c);
	return c;
}

#endif /* __HASH_H_ */
