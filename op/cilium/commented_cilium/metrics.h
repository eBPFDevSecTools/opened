/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Data metrics collection functions
 *
 */
#ifndef __LIB_METRICS__
#define __LIB_METRICS__

#include "common.h"
#include "utils.h"
#include "maps.h"
#include "dbg.h"

/**
 * update_metrics
 * @direction:	1: Ingress 2: Egress
 * @reason:	reason for forwarding or dropping packet.
 *		reason is 0 if packet is being forwarded, else reason
 *		is the drop error code.
 * Update the metrics map.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 43,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/metrics.h",
  "funcName": "update_metrics",
  "developer_inline_comments": [],
  "updateMaps": [
    " METRICS_MAP"
  ],
  "readMaps": [
    "  METRICS_MAP"
  ],
  "input": [
    "__u64 bytes",
    " __u8 direction",
    " __u8 reason"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "map_lookup_elem",
    "map_update_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "sk_msg",
    "xdp",
    "lwt_in",
    "flow_dissector",
    "sched_act",
    "tracepoint",
    "kprobe",
    "lwt_xmit",
    "sock_ops",
    "raw_tracepoint",
    "sk_reuseport",
    "raw_tracepoint_writable",
    "sk_skb",
    "lwt_out",
    "socket_filter",
    "cgroup_skb",
    "cgroup_device",
    "perf_event",
    "cgroup_sock",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline void update_metrics (__u64 bytes, __u8 direction, __u8 reason)\n",
    "{\n",
    "    struct metrics_value *entry, new_entry = {};\n",
    "    struct metrics_key key = {}\n",
    "    ;\n",
    "    key.reason = reason;\n",
    "    key.dir = direction;\n",
    "    entry = map_lookup_elem (& METRICS_MAP, & key);\n",
    "    if (entry) {\n",
    "        entry->count += 1;\n",
    "        entry->bytes += bytes;\n",
    "    }\n",
    "    else {\n",
    "        new_entry.count = 1;\n",
    "        new_entry.bytes = bytes;\n",
    "        map_update_elem (&METRICS_MAP, &key, &new_entry, 0);\n",
    "    }\n",
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
static __always_inline void update_metrics(__u64 bytes, __u8 direction,
					   __u8 reason)
{
	struct metrics_value *entry, new_entry = {};
	struct metrics_key key = {};

	key.reason = reason;
	key.dir    = direction;


	entry = map_lookup_elem(&METRICS_MAP, &key);
	if (entry) {
		entry->count += 1;
		entry->bytes += bytes;
	} else {
		new_entry.count = 1;
		new_entry.bytes = bytes;
		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
	}
}

/**
 * ct_to_metrics_dir
 * @direction:	1: Ingress 2: Egress 3: Service
 * Convert a CT direction into the corresponding one for metrics.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 62,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/metrics.h",
  "funcName": "ct_to_metrics_dir",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "enum ct_dir ct_dir"
  ],
  "output": "static__always_inlineenummetric_dir",
  "helper": [],
  "compatibleHookpoints": [
    "sched_cls",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "sk_msg",
    "xdp",
    "lwt_in",
    "flow_dissector",
    "sched_act",
    "tracepoint",
    "kprobe",
    "lwt_xmit",
    "sock_ops",
    "raw_tracepoint",
    "sk_reuseport",
    "raw_tracepoint_writable",
    "sk_skb",
    "lwt_out",
    "socket_filter",
    "cgroup_skb",
    "cgroup_device",
    "perf_event",
    "cgroup_sock",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline enum metric_dir ct_to_metrics_dir (enum ct_dir ct_dir)\n",
    "{\n",
    "    switch (ct_dir) {\n",
    "    case CT_INGRESS :\n",
    "        return METRIC_INGRESS;\n",
    "    case CT_EGRESS :\n",
    "        return METRIC_EGRESS;\n",
    "    case CT_SERVICE :\n",
    "        return METRIC_SERVICE;\n",
    "    default :\n",
    "        return 0;\n",
    "    }\n",
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
static __always_inline enum metric_dir ct_to_metrics_dir(enum ct_dir ct_dir)
{
	switch (ct_dir) {
	case CT_INGRESS:
		return METRIC_INGRESS;
	case CT_EGRESS:
		return METRIC_EGRESS;
	case CT_SERVICE:
		return METRIC_SERVICE;
	default:
		return 0;
	}
}

#endif /* __LIB_METRICS__ */
