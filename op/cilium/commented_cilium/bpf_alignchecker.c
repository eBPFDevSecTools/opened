// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Ensure declaration of notification event types */
#define DEBUG
#define TRACE_NOTIFY
#define DROP_NOTIFY
#define POLICY_VERDICT_NOTIFY
#define ENABLE_VTEP
#define ENABLE_CAPTURE
#undef ENABLE_ARP_RESPONDER

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include "node_config.h"
#include "lib/conntrack.h"
#include "lib/dbg.h"
#include "lib/drop.h"
#include "lib/ipv4.h"
#define SKIP_UNDEF_LPM_LOOKUP_FN
#include "lib/maps.h"
#include "lib/nat.h"
#include "lib/trace.h"
#include "lib/policy_log.h"
#include "lib/pcap.h"
#include "sockops/bpf_sockops.h"

/* DECLARE declares a unique usage of the union or struct 'x' on the stack.
 *
 * To prevent compiler from optimizing away the var, we pass a reference
 * to the var to a BPF helper function which accepts a reference as
 * an argument.
 */
#define DECLARE(type)			\
{					\
	type s = {};			\
	trace_printk("%p", 1, &s);	\
}

/* This function is a placeholder for C struct definitions shared with Go,
 * it is never executed.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 44,
  "endLine": 99,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_alignchecker.c",
  "funcName": "main",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of Cilium */"
    },
    {
      "start_line": 4,
      "end_line": 4,
      "text": "/* Ensure declaration of notification event types */"
    },
    {
      "start_line": 29,
      "end_line": 34,
      "text": "/* DECLARE declares a unique usage of the union or struct 'x' on the stack.\n *\n * To prevent compiler from optimizing away the var, we pass a reference\n * to the var to a BPF helper function which accepts a reference as\n * an argument.\n */"
    },
    {
      "start_line": 41,
      "end_line": 43,
      "text": "/* This function is a placeholder for C struct definitions shared with Go,\n * it is never executed.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_xmit",
    "sock_ops",
    "flow_dissector",
    "raw_tracepoint",
    "cgroup_sysctl",
    "tracepoint",
    "kprobe",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event",
    "xdp",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "int main (void)\n",
    "{\n",
    "    DECLARE (struct ipv4_ct_tuple);\n",
    "    DECLARE (struct ipv6_ct_tuple);\n",
    "    DECLARE (struct ct_entry);\n",
    "    DECLARE (struct ipcache_key);\n",
    "    DECLARE (struct remote_endpoint_info);\n",
    "    DECLARE (struct lb4_key);\n",
    "    DECLARE (struct lb4_service);\n",
    "    DECLARE (struct lb4_backend);\n",
    "    DECLARE (struct lb6_key);\n",
    "    DECLARE (struct lb6_service);\n",
    "    DECLARE (struct lb6_backend);\n",
    "    DECLARE (struct endpoint_key);\n",
    "    DECLARE (struct endpoint_info);\n",
    "    DECLARE (struct metrics_key);\n",
    "    DECLARE (struct metrics_value);\n",
    "    DECLARE (struct sock_key);\n",
    "    DECLARE (struct policy_key);\n",
    "    DECLARE (struct policy_entry);\n",
    "    DECLARE (struct ipv4_nat_entry);\n",
    "    DECLARE (struct ipv6_nat_entry);\n",
    "    DECLARE (struct trace_notify);\n",
    "    DECLARE (struct drop_notify);\n",
    "    DECLARE (struct policy_verdict_notify);\n",
    "    DECLARE (struct debug_msg);\n",
    "    DECLARE (struct debug_capture_msg);\n",
    "    DECLARE (struct ipv4_revnat_tuple);\n",
    "    DECLARE (struct ipv4_revnat_entry);\n",
    "    DECLARE (struct ipv6_revnat_tuple);\n",
    "    DECLARE (struct ipv6_revnat_entry);\n",
    "    DECLARE (struct ipv4_frag_id);\n",
    "    DECLARE (struct ipv4_frag_l4ports);\n",
    "    DECLARE (union macaddr);\n",
    "    DECLARE (struct lb4_affinity_key);\n",
    "    DECLARE (struct lb6_affinity_key);\n",
    "    DECLARE (struct lb_affinity_val);\n",
    "    DECLARE (struct lb_affinity_match);\n",
    "    DECLARE (struct lb4_src_range_key);\n",
    "    DECLARE (struct lb6_src_range_key);\n",
    "    DECLARE (struct edt_id);\n",
    "    DECLARE (struct edt_info);\n",
    "    DECLARE (struct egress_gw_policy_key);\n",
    "    DECLARE (struct egress_gw_policy_entry);\n",
    "    DECLARE (struct vtep_key);\n",
    "    DECLARE (struct vtep_value);\n",
    "    DECLARE (struct capture4_wcard);\n",
    "    DECLARE (struct capture6_wcard);\n",
    "    DECLARE (struct capture_rule);\n",
    "    DECLARE (struct srv6_vrf_key4);\n",
    "    DECLARE (struct srv6_vrf_key6);\n",
    "    DECLARE (struct srv6_policy_key4);\n",
    "    DECLARE (struct srv6_policy_key6);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dump_kern_jiffies",
    "pin_to_cpu",
    "fix_priority",
    "prep_kern_jiffies",
    "getopt",
    "fprintf",
    "fetch_kern_jiffies",
    "nanosleep",
    "strerror"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " Print and debug all the existing variables (especially fast path  sections that printk is not appropriate for) ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
int main(void)
{
	DECLARE(struct ipv4_ct_tuple);
	DECLARE(struct ipv6_ct_tuple);
	DECLARE(struct ct_entry);
	DECLARE(struct ipcache_key);
	DECLARE(struct remote_endpoint_info);
	DECLARE(struct lb4_key);
	DECLARE(struct lb4_service);
	DECLARE(struct lb4_backend);
	DECLARE(struct lb6_key);
	DECLARE(struct lb6_service);
	DECLARE(struct lb6_backend);
	DECLARE(struct endpoint_key);
	DECLARE(struct endpoint_info);
	DECLARE(struct metrics_key);
	DECLARE(struct metrics_value);
	DECLARE(struct sock_key);
	DECLARE(struct policy_key);
	DECLARE(struct policy_entry);
	DECLARE(struct ipv4_nat_entry);
	DECLARE(struct ipv6_nat_entry);
	DECLARE(struct trace_notify);
	DECLARE(struct drop_notify);
	DECLARE(struct policy_verdict_notify);
	DECLARE(struct debug_msg);
	DECLARE(struct debug_capture_msg);
	DECLARE(struct ipv4_revnat_tuple);
	DECLARE(struct ipv4_revnat_entry);
	DECLARE(struct ipv6_revnat_tuple);
	DECLARE(struct ipv6_revnat_entry);
	DECLARE(struct ipv4_frag_id);
	DECLARE(struct ipv4_frag_l4ports);
	DECLARE(union macaddr);
	DECLARE(struct lb4_affinity_key);
	DECLARE(struct lb6_affinity_key);
	DECLARE(struct lb_affinity_val);
	DECLARE(struct lb_affinity_match);
	DECLARE(struct lb4_src_range_key);
	DECLARE(struct lb6_src_range_key);
	DECLARE(struct edt_id);
	DECLARE(struct edt_info);
	DECLARE(struct egress_gw_policy_key);
	DECLARE(struct egress_gw_policy_entry);
	DECLARE(struct vtep_key);
	DECLARE(struct vtep_value);
	DECLARE(struct capture4_wcard);
	DECLARE(struct capture6_wcard);
	DECLARE(struct capture_rule);
	DECLARE(struct srv6_vrf_key4);
	DECLARE(struct srv6_vrf_key6);
	DECLARE(struct srv6_policy_key4);
	DECLARE(struct srv6_policy_key6);

	return 0;
}
