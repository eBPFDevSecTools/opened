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
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l4.h",
  "funcName": "l4_modify_port",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of Cilium */"
    },
    {
      "start_line": 19,
      "end_line": 35,
      "text": "/**\n * Modify L4 port and correct checksum\n * @arg ctx:      packet\n * @arg l4_off:   offset to L4 header\n * @arg off:      offset from L4 header to source or destination port\n * @arg csum_off: offset from L4 header to 16bit checksum field in L4 header\n * @arg port:     new port value\n * @arg old_port: old port value (for checksum correction)\n *\n * Overwrites a TCP or UDP port with new value and fixes up the checksum\n * in the L4 header and of ctx->csum.\n *\n * NOTE: Calling this function will invalidate any pkt context offset\n * validation for direct packet access.\n *\n * Return 0 on success or a negative DROP_* reason\n */"
    }
  ],
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
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline int l4_modify_port (struct  __ctx_buff *ctx, int l4_off, int off, struct csum_offset *csum_off, __be16 port, __be16 old_port)\n",
    "{\n",
    "    if (csum_l4_replace (ctx, l4_off, csum_off, old_port, port, sizeof (port)) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    if (ctx_store_bytes (ctx, l4_off + off, &port, sizeof (port), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_l4_replace",
    "ctx_store_bytes"
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
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/l4.h",
  "funcName": "l4_load_port",
  "developer_inline_comments": [],
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
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline int l4_load_port (struct  __ctx_buff *ctx, int off, __be16 *port)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off, port, sizeof (__be16));\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes"
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
static __always_inline int l4_load_port(struct __ctx_buff *ctx, int off,
					__be16 *port)
{
	return ctx_load_bytes(ctx, off, port, sizeof(__be16));
}
#endif
