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
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 34,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lxc.h",
  "funcName": "is_valid_lxc_src_ip",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6hdr * ip6 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int is_valid_lxc_src_ip (struct ipv6hdr * ip6 __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    union v6addr valid = {}\n",
    "    ;\n",
    "    BPF_V6 (valid, LXC_IP);\n",
    "    return !ipv6_addrcmp ((union v6addr *) &ip6->saddr, &valid);\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_addrcmp",
    "BPF_V6"
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
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 36,
  "endLine": 45,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lxc.h",
  "funcName": "is_valid_lxc_src_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr * ip4 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int is_valid_lxc_src_ipv4 (const struct iphdr * ip4 __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    return ip4->saddr == LXC_IPV4;\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 47,
  "endLine": 51,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lxc.h",
  "funcName": "is_valid_lxc_src_ip",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6hdr * ip6 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int is_valid_lxc_src_ip (struct ipv6hdr * ip6 __maybe_unused)\n",
    "{\n",
    "    return 1;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_addrcmp",
    "BPF_V6"
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
static __always_inline
int is_valid_lxc_src_ip(struct ipv6hdr *ip6 __maybe_unused)
{
	return 1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 53,
  "endLine": 57,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lxc.h",
  "funcName": "is_valid_lxc_src_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr * ip4 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_out",
    "lwt_xmit",
    "flow_dissector",
    "cgroup_sock_addr",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sysctl",
    "cgroup_skb",
    "socket_filter",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "sched_cls",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline int is_valid_lxc_src_ipv4 (struct iphdr * ip4 __maybe_unused)\n",
    "{\n",
    "    return 1;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __always_inline
int is_valid_lxc_src_ipv4(struct iphdr *ip4 __maybe_unused)
{
	return 1;
}
#endif

#endif /* __LIB_LXC_H_ */
