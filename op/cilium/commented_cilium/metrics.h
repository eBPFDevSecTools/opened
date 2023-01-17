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
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\tentry ",
        "inpVar": [
          " &METRICS_MAP",
          " &key"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t&METRICS_MAP",
          " &key",
          " &new_entry",
          " 0"
        ]
      }
    ]
  },
  "startLine": 24,
  "endLine": 43,
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/metrics.h",
  "funcName": "update_metrics",
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
    "map_update_elem",
    "map_lookup_elem"
  ],
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
    "socket_filter",
    "raw_tracepoint",
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/lib/metrics.h",
  "funcName": "ct_to_metrics_dir",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "enum ct_dir ct_dir"
  ],
  "output": "static__always_inlineenummetric_dir",
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
