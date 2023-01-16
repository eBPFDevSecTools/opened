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
  "capability": [],
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
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/metrics.h",
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
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "raw_tracepoint_writable",
    "socket_filter",
    "sched_act",
    "sk_reuseport",
    "xdp",
    "sk_msg",
    "lwt_in",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_xmit",
    "cgroup_device",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "tracepoint",
    "raw_tracepoint",
    "sched_cls",
    "lwt_out"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 62,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/metrics.h",
  "funcName": "ct_to_metrics_dir",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "enum ct_dir ct_dir"
  ],
  "output": "static__always_inlineenummetric_dir",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
