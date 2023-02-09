/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_L4_H_
#define __LIB_L4_H_

#include <linux/tcp.h>
#include <linux/udp.h>
#include "common.h"
#include "dbg.h"
#include "csum.h"

#define TCP_DPORT_OFF (offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF (offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF (offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF (offsetof(struct udphdr, source))


/**
 * Modify L4 port and correct checksum
 * @arg ctx:      packet
 * @arg l4_off:   offset to L4 header
 * @arg off:      offset from L4 header to source or destination port
 * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header
 * @arg port:     new port value
 * @arg old_port: old port value (for checksum correction)
 *
 * Overwrites a TCP or UDP port with new value and fixes up the checksum
 * in the L4 header and of ctx->csum.
 *
 * NOTE: Calling this function will invalidate any pkt context offset
 * validation for direct packet access.
 *
 * Return 0 on success or a negative DROP_* reason
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 36,
  "endLine": 47,
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/l4.h",
  "funcName": "l4_modify_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l4_off",
    " int off",
    " struct csum_offset *csum_off",
    " __be16 port",
    " __be16 old_port"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "lwt_xmit",
    "cgroup_sock_addr",
    "sock_ops",
    "sk_skb",
    "lwt_seg6local",
    "perf_event",
    "cgroup_sysctl",
    "cgroup_sock",
    "xdp",
    "socket_filter",
    "cgroup_skb",
    "kprobe",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "sched_cls",
    "sched_act",
    "raw_tracepoint",
    "flow_dissector",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "tracepoint"
  ],
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
static __always_inline int l4_modify_port(struct __ctx_buff *ctx, int l4_off,
					  int off, struct csum_offset *csum_off,
					  __be16 port, __be16 old_port)
{
	if (csum_l4_replace(ctx, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
		return DROP_CSUM_L4;

	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
		return DROP_WRITE_ERROR;

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 49,
  "endLine": 53,
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/l4.h",
  "funcName": "l4_load_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int off",
    " __be16 *port"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "lwt_xmit",
    "cgroup_sock_addr",
    "sock_ops",
    "sk_skb",
    "lwt_seg6local",
    "perf_event",
    "cgroup_sysctl",
    "cgroup_sock",
    "xdp",
    "socket_filter",
    "cgroup_skb",
    "kprobe",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "sched_cls",
    "sched_act",
    "raw_tracepoint",
    "flow_dissector",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "tracepoint"
  ],
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
static __always_inline int l4_load_port(struct __ctx_buff *ctx, int off,
					__be16 *port)
{
	return ctx_load_bytes(ctx, off, port, sizeof(__be16));
}
#endif
