/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LB_H_
#define __LB_H_

#include "csum.h"
#include "conntrack.h"
#include "ipv4.h"
#include "hash.h"
#include "ids.h"
#include "nat_46x64.h"

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct lb6_reverse_nat);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_REVERSE_NAT_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb6_key);
	__type(value, struct lb6_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_SERVICES_MAP_V2 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb6_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB6_BACKEND_MAP_V2 __section_maps_btf;

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb6_affinity_key);
	__type(value, struct lb_affinity_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
} LB6_AFFINITY_MAP __section_maps_btf;
#endif

#ifdef ENABLE_SRC_RANGE_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb6_src_range_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_SRC_RANGE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} LB6_SRC_RANGE_MAP __section_maps_btf;
#endif

#ifdef ENABLE_HEALTH_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __sock_cookie);
	__type(value, struct lb6_health);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
} LB6_HEALTH_MAP __section_maps_btf;
#endif

#if LB_SELECTION == LB_SELECTION_MAGLEV
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u16);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Maglev inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(key_size, sizeof(__u32));
		__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
		__uint(max_entries, 1);
	});
} LB6_MAGLEV_MAP_OUTER __section_maps_btf;
#endif /* LB_SELECTION == LB_SELECTION_MAGLEV */
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct lb4_reverse_nat);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_REVERSE_NAT_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_key);
	__type(value, struct lb4_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_SERVICE_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_SERVICES_MAP_V2 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct lb4_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB4_BACKEND_MAP_V2 __section_maps_btf;

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct lb4_affinity_key);
	__type(value, struct lb_affinity_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
} LB4_AFFINITY_MAP __section_maps_btf;
#endif

#ifdef ENABLE_SRC_RANGE_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb4_src_range_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_SRC_RANGE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} LB4_SRC_RANGE_MAP __section_maps_btf;
#endif

#ifdef ENABLE_HEALTH_CHECK
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __sock_cookie);
	__type(value, struct lb4_health);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES);
} LB4_HEALTH_MAP __section_maps_btf;
#endif

#if LB_SELECTION == LB_SELECTION_MAGLEV
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u16);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
	/* Maglev inner map definition */
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__uint(key_size, sizeof(__u32));
		__uint(value_size, sizeof(__u32) * LB_MAGLEV_LUT_SIZE);
		__uint(max_entries, 1);
	});
} LB4_MAGLEV_MAP_OUTER __section_maps_btf;
#endif /* LB_SELECTION == LB_SELECTION_MAGLEV */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_SESSION_AFFINITY
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb_affinity_match);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} LB_AFFINITY_MATCH_MAP __section_maps_btf;
#endif

#define REV_NAT_F_TUPLE_SADDR	1
#ifndef DSR_XLATE_MODE
# define DSR_XLATE_MODE		0
# define DSR_XLATE_FRONTEND	1
#endif
#ifdef LB_DEBUG
#define cilium_dbg_lb cilium_dbg
#else
#define cilium_dbg_lb(a, b, c, d)
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 192,
  "endLine": 196,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_loadbalancer",
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
      "start_line": 81,
      "end_line": 81,
      "text": "/* Maglev inner map definition */"
    },
    {
      "start_line": 89,
      "end_line": 89,
      "text": "/* LB_SELECTION == LB_SELECTION_MAGLEV */"
    },
    {
      "start_line": 90,
      "end_line": 90,
      "text": "/* ENABLE_IPV6 */"
    },
    {
      "start_line": 159,
      "end_line": 159,
      "text": "/* Maglev inner map definition */"
    },
    {
      "start_line": 167,
      "end_line": 167,
      "text": "/* LB_SELECTION == LB_SELECTION_MAGLEV */"
    },
    {
      "start_line": 168,
      "end_line": 168,
      "text": "/* ENABLE_IPV4 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_loadbalancer (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_LOADBALANCER;\n",
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
bool lb4_svc_is_loadbalancer(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_LOADBALANCER;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 198,
  "endLine": 202,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_loadbalancer",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_loadbalancer (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_LOADBALANCER;\n",
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
bool lb6_svc_is_loadbalancer(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_LOADBALANCER;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 204,
  "endLine": 212,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_nodeport",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": "/* ENABLE_NODEPORT */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_nodeport (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    return svc->flags & SVC_FLAG_NODEPORT;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
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
bool lb4_svc_is_nodeport(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->flags & SVC_FLAG_NODEPORT;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 214,
  "endLine": 222,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_nodeport",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": "/* ENABLE_NODEPORT */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_nodeport (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    return svc->flags & SVC_FLAG_NODEPORT;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
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
bool lb6_svc_is_nodeport(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return svc->flags & SVC_FLAG_NODEPORT;
#else
	return false;
#endif /* ENABLE_NODEPORT */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 224,
  "endLine": 228,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_external_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_external_ip (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_EXTERNAL_IP;\n",
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
bool lb4_svc_is_external_ip(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_EXTERNAL_IP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 230,
  "endLine": 234,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_external_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_external_ip (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_EXTERNAL_IP;\n",
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
bool lb6_svc_is_external_ip(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_EXTERNAL_IP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 236,
  "endLine": 240,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_hostport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_hostport (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_HOSTPORT;\n",
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
bool lb4_svc_is_hostport(const struct lb4_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_HOSTPORT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 242,
  "endLine": 246,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_hostport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_hostport (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_HOSTPORT;\n",
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
bool lb6_svc_is_hostport(const struct lb6_service *svc __maybe_unused)
{
	return svc->flags & SVC_FLAG_HOSTPORT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 248,
  "endLine": 256,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_has_src_range_check",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": "/* ENABLE_SRC_RANGE_CHECK */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_has_src_range_check (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_SRC_RANGE_CHECK\n",
    "    return svc->flags & SVC_FLAG_SOURCE_RANGE;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif /* ENABLE_SRC_RANGE_CHECK */\n",
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
bool lb4_svc_has_src_range_check(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	return svc->flags & SVC_FLAG_SOURCE_RANGE;
#else
	return false;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 258,
  "endLine": 266,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_has_src_range_check",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": "/* ENABLE_SRC_RANGE_CHECK */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_has_src_range_check (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_SRC_RANGE_CHECK\n",
    "    return svc->flags & SVC_FLAG_SOURCE_RANGE;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif /* ENABLE_SRC_RANGE_CHECK */\n",
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
bool lb6_svc_has_src_range_check(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	return svc->flags & SVC_FLAG_SOURCE_RANGE;
#else
	return false;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 268,
  "endLine": 271,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb_skip_l4_dnat",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb_skip_l4_dnat (void)\n",
    "{\n",
    "    return DSR_XLATE_MODE == DSR_XLATE_FRONTEND;\n",
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
static __always_inline bool lb_skip_l4_dnat(void)
{
	return DSR_XLATE_MODE == DSR_XLATE_FRONTEND;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 273,
  "endLine": 277,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_local_scope",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_local_scope (const struct lb4_service *svc)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_LOCAL_SCOPE;\n",
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
bool lb4_svc_is_local_scope(const struct lb4_service *svc)
{
	return svc->flags & SVC_FLAG_LOCAL_SCOPE;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 279,
  "endLine": 283,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_local_scope",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_local_scope (const struct lb6_service *svc)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_LOCAL_SCOPE;\n",
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
bool lb6_svc_is_local_scope(const struct lb6_service *svc)
{
	return svc->flags & SVC_FLAG_LOCAL_SCOPE;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 285,
  "endLine": 289,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_affinity",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_affinity (const struct lb4_service *svc)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_AFFINITY;\n",
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
bool lb4_svc_is_affinity(const struct lb4_service *svc)
{
	return svc->flags & SVC_FLAG_AFFINITY;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 291,
  "endLine": 295,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_affinity",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_affinity (const struct lb6_service *svc)\n",
    "{\n",
    "    return svc->flags & SVC_FLAG_AFFINITY;\n",
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
bool lb6_svc_is_affinity(const struct lb6_service *svc)
{
	return svc->flags & SVC_FLAG_AFFINITY;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 297,
  "endLine": 300,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb_svc_is_routable",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 flags"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool __lb_svc_is_routable (__u8 flags)\n",
    "{\n",
    "    return (flags & SVC_FLAG_ROUTABLE) != 0;\n",
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
static __always_inline bool __lb_svc_is_routable(__u8 flags)
{
	return (flags & SVC_FLAG_ROUTABLE) != 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 302,
  "endLine": 306,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_routable",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_routable (const struct lb4_service *svc)\n",
    "{\n",
    "    return __lb_svc_is_routable (svc->flags);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb_svc_is_routable"
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
bool lb4_svc_is_routable(const struct lb4_service *svc)
{
	return __lb_svc_is_routable(svc->flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 308,
  "endLine": 312,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_routable",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_routable (const struct lb6_service *svc)\n",
    "{\n",
    "    return __lb_svc_is_routable (svc->flags);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb_svc_is_routable"
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
bool lb6_svc_is_routable(const struct lb6_service *svc)
{
	return __lb_svc_is_routable(svc->flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 314,
  "endLine": 318,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_localredirect",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_localredirect (const struct lb4_service *svc)\n",
    "{\n",
    "    return svc->flags2 & SVC_FLAG_LOCALREDIRECT;\n",
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
bool lb4_svc_is_localredirect(const struct lb4_service *svc)
{
	return svc->flags2 & SVC_FLAG_LOCALREDIRECT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 320,
  "endLine": 328,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_svc_is_l7loadbalancer",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_svc_is_l7loadbalancer (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    return svc->flags2 & SVC_FLAG_L7LOADBALANCER;\n",
    "\n",
    "#else\n",
    "    return false;\n",
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
bool lb4_svc_is_l7loadbalancer(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_L7_LB
	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
#else
	return false;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 330,
  "endLine": 338,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_svc_is_l7loadbalancer",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_svc_is_l7loadbalancer (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    return svc->flags2 & SVC_FLAG_L7LOADBALANCER;\n",
    "\n",
    "#else\n",
    "    return false;\n",
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
bool lb6_svc_is_l7loadbalancer(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_L7_LB
	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
#else
	return false;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 340,
  "endLine": 380,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "extract_l4_port",
  "developer_inline_comments": [
    {
      "start_line": 24,
      "end_line": 24,
      "text": "/* Port offsets for UDP and TCP are the same */"
    },
    {
      "start_line": 32,
      "end_line": 32,
      "text": "/* No need to perform a service lookup for ICMP packets */"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "/* Pass unknown L4 to stack */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 nexthdr",
    " int l4_off",
    " enum ct_dir dir __maybe_unused",
    " __be16 *port",
    " __maybe_unused struct iphdr *ip4"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int extract_l4_port (struct  __ctx_buff *ctx, __u8 nexthdr, int l4_off, enum ct_dir dir __maybe_unused, __be16 *port, __maybe_unused struct iphdr *ip4)\n",
    "{\n",
    "    int ret;\n",
    "    switch (nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "\n",
    "#ifdef ENABLE_IPV4_FRAGMENTS\n",
    "        if (ip4) {\n",
    "            struct ipv4_frag_l4ports ports = {}\n",
    "            ;\n",
    "            ret = ipv4_handle_fragmentation (ctx, ip4, l4_off, dir, & ports, NULL);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "            *port = ports.dport;\n",
    "            break;\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        ret = l4_load_port (ctx, l4_off + TCP_DPORT_OFF, port);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        break;\n",
    "    case IPPROTO_ICMPV6 :\n",
    "    case IPPROTO_ICMP :\n",
    "        return DROP_NO_SERVICE;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_L4;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "IS_ERR",
    "l4_load_port",
    "ipv4_handle_fragmentation"
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
static __always_inline int extract_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
					   int l4_off,
					   enum ct_dir dir __maybe_unused,
					   __be16 *port,
					   __maybe_unused struct iphdr *ip4)
{
	int ret;

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_IPV4_FRAGMENTS
		if (ip4) {
			struct ipv4_frag_l4ports ports = { };

			ret = ipv4_handle_fragmentation(ctx, ip4, l4_off,
							dir, &ports, NULL);
			if (IS_ERR(ret))
				return ret;
			*port = ports.dport;
			break;
		}
#endif
		/* Port offsets for UDP and TCP are the same */
		ret = l4_load_port(ctx, l4_off + TCP_DPORT_OFF, port);
		if (IS_ERR(ret))
			return ret;
		break;

	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		/* No need to perform a service lookup for ICMP packets */
		return DROP_NO_SERVICE;

	default:
		/* Pass unknown L4 to stack */
		return DROP_UNKNOWN_L4;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 382,
  "endLine": 416,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "reverse_map_l4_port",
  "developer_inline_comments": [
    {
      "start_line": 12,
      "end_line": 12,
      "text": "/* Port offsets for UDP and TCP are the same */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 nexthdr",
    " __be16 port",
    " int l4_off",
    " struct csum_offset *csum_off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int reverse_map_l4_port (struct  __ctx_buff *ctx, __u8 nexthdr, __be16 port, int l4_off, struct csum_offset *csum_off)\n",
    "{\n",
    "    switch (nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "        if (port) {\n",
    "            __be16 old_port;\n",
    "            int ret;\n",
    "            ret = l4_load_port (ctx, l4_off + TCP_SPORT_OFF, & old_port);\n",
    "            if (IS_ERR (ret))\n",
    "                return ret;\n",
    "            if (port != old_port) {\n",
    "                ret = l4_modify_port (ctx, l4_off, TCP_SPORT_OFF, csum_off, port, old_port);\n",
    "                if (IS_ERR (ret))\n",
    "                    return ret;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case IPPROTO_ICMPV6 :\n",
    "    case IPPROTO_ICMP :\n",
    "        return CTX_ACT_OK;\n",
    "    default :\n",
    "        return DROP_UNKNOWN_L4;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "IS_ERR",
    "l4_load_port"
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
static __always_inline int reverse_map_l4_port(struct __ctx_buff *ctx, __u8 nexthdr,
					       __be16 port, int l4_off,
					       struct csum_offset *csum_off)
{
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (port) {
			__be16 old_port;
			int ret;

			/* Port offsets for UDP and TCP are the same */
			ret = l4_load_port(ctx, l4_off + TCP_SPORT_OFF, &old_port);
			if (IS_ERR(ret))
				return ret;

			if (port != old_port) {
				ret = l4_modify_port(ctx, l4_off, TCP_SPORT_OFF,
						     csum_off, port, old_port);
				if (IS_ERR(ret))
					return ret;
			}
		}
		break;

	case IPPROTO_ICMPV6:
	case IPPROTO_ICMP:
		return CTX_ACT_OK;

	default:
		return DROP_UNKNOWN_L4;
	}

	return 0;
}

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 419,
  "endLine": 459,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_rev_nat",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct ipv6_ct_tuple *tuple",
    " int flags",
    " struct lb6_reverse_nat *nat"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "lwt_out",
    "lwt_seg6local",
    "sched_act",
    "sched_cls",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int __lb6_rev_nat (struct  __ctx_buff *ctx, int l4_off, struct csum_offset *csum_off, struct ipv6_ct_tuple *tuple, int flags, struct lb6_reverse_nat *nat)\n",
    "{\n",
    "    union v6addr old_saddr;\n",
    "    union v6addr tmp;\n",
    "    __u8 *new_saddr;\n",
    "    __be32 sum;\n",
    "    int ret;\n",
    "    cilium_dbg_lb (ctx, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);\n",
    "    if (nat->port) {\n",
    "        ret = reverse_map_l4_port (ctx, tuple -> nexthdr, nat -> port, l4_off, csum_off);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (flags & REV_NAT_F_TUPLE_SADDR) {\n",
    "        ipv6_addr_copy (&old_saddr, &tuple->saddr);\n",
    "        ipv6_addr_copy (&tuple->saddr, &nat->address);\n",
    "        new_saddr = tuple->saddr.addr;\n",
    "    }\n",
    "    else {\n",
    "        if (ipv6_load_saddr (ctx, ETH_HLEN, &old_saddr) < 0)\n",
    "            return DROP_INVALID;\n",
    "        ipv6_addr_copy (&tmp, &nat->address);\n",
    "        new_saddr = tmp.addr;\n",
    "    }\n",
    "    ret = ipv6_store_saddr (ctx, new_saddr, ETH_HLEN);\n",
    "    if (IS_ERR (ret))\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (old_saddr.addr, 16, new_saddr, 16, 0);\n",
    "    if (csum_l4_replace (ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv6_store_saddr",
    "ipv6_load_saddr",
    "IS_ERR",
    "csum_l4_replace",
    "ipv6_addr_copy",
    "cilium_dbg_lb",
    "reverse_map_l4_port"
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
static __always_inline int __lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv6_ct_tuple *tuple, int flags,
					 struct lb6_reverse_nat *nat)
{
	union v6addr old_saddr;
	union v6addr tmp;
	__u8 *new_saddr;
	__be32 sum;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT, nat->address.p4, nat->port);

	if (nat->port) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		ipv6_addr_copy(&old_saddr, &tuple->saddr);
		ipv6_addr_copy(&tuple->saddr, &nat->address);
		new_saddr = tuple->saddr.addr;
	} else {
		if (ipv6_load_saddr(ctx, ETH_HLEN, &old_saddr) < 0)
			return DROP_INVALID;

		ipv6_addr_copy(&tmp, &nat->address);
		new_saddr = tmp.addr;
	}

	ret = ipv6_store_saddr(ctx, new_saddr, ETH_HLEN);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(old_saddr.addr, 16, new_saddr, 16, 0);
	if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}

/** Perform IPv6 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
 * @arg saddr_tuple	If set, tuple address will be updated with new source address
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
  "startLine": 470,
  "endLine": 482,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_rev_nat",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 9,
      "text": "/** Perform IPv6 reverse NAT based on reverse NAT index\n * @arg ctx\t\tpacket\n * @arg l4_off\t\toffset to L4\n * @arg csum_off\toffset to L4 checksum field\n * @arg csum_flags\tchecksum flags\n * @arg index\t\treverse NAT index\n * @arg tuple\t\ttuple\n * @arg saddr_tuple\tIf set, tuple address will be updated with new source address\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  LB6_REVERSE_NAT_MAP"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l4_off",
    " struct csum_offset *csum_off",
    " __u16 index",
    " struct ipv6_ct_tuple *tuple",
    " int flags"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline int lb6_rev_nat (struct  __ctx_buff *ctx, int l4_off, struct csum_offset *csum_off, __u16 index, struct ipv6_ct_tuple *tuple, int flags)\n",
    "{\n",
    "    struct lb6_reverse_nat *nat;\n",
    "    cilium_dbg_lb (ctx, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);\n",
    "    nat = map_lookup_elem (& LB6_REVERSE_NAT_MAP, & index);\n",
    "    if (nat == NULL)\n",
    "        return 0;\n",
    "    return __lb6_rev_nat (ctx, l4_off, csum_off, tuple, flags, nat);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_lb",
    "__lb6_rev_nat"
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
static __always_inline int lb6_rev_nat(struct __ctx_buff *ctx, int l4_off,
				       struct csum_offset *csum_off, __u16 index,
				       struct ipv6_ct_tuple *tuple, int flags)
{
	struct lb6_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB6_REVERSE_NAT_LOOKUP, index, 0);
	nat = map_lookup_elem(&LB6_REVERSE_NAT_MAP, &index);
	if (nat == NULL)
		return 0;

	return __lb6_rev_nat(ctx, l4_off, csum_off, tuple, flags, nat);
}

/** Extract IPv6 LB key from packet
 * @arg ctx		Packet
 * @arg tuple		Tuple
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset and flags
 * @arg dir		Flow direction
 *
 * Expects the ctx to be validated for direct packet access up to L4. Fills
 * lb6_key based on L4 nexthdr.
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 500,
  "endLine": 516,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_extract_key",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/** Extract IPv6 LB key from packet\n * @arg ctx\t\tPacket\n * @arg tuple\t\tTuple\n * @arg l4_off\t\tOffset to L4 header\n * @arg key\t\tPointer to store LB key in\n * @arg csum_off\tPointer to store L4 checksum field offset and flags\n * @arg dir\t\tFlow direction\n *\n * Expects the ctx to be validated for direct packet access up to L4. Fills\n * lb6_key based on L4 nexthdr.\n *\n * Returns:\n *   - CTX_ACT_OK on successful extraction\n *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)\n *   - Negative error code\n */"
    },
    {
      "start_line": 25,
      "end_line": 25,
      "text": "/* FIXME(brb): set after adding support for different L4 protocols in LB */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct ipv6_ct_tuple *tuple",
    " int l4_off __maybe_unused",
    " struct lb6_key *key",
    " struct csum_offset *csum_off",
    " enum ct_dir dir"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int lb6_extract_key (struct  __ctx_buff * ctx __maybe_unused, struct ipv6_ct_tuple *tuple, int l4_off __maybe_unused, struct lb6_key *key, struct csum_offset *csum_off, enum ct_dir dir)\n",
    "{\n",
    "    union v6addr *addr;\n",
    "    key->proto = 0;\n",
    "    addr = (dir == CT_INGRESS) ? &tuple->saddr : &tuple->daddr;\n",
    "    ipv6_addr_copy (&key->address, addr);\n",
    "    csum_l4_offset_and_flags (tuple->nexthdr, csum_off);\n",
    "    return extract_l4_port (ctx, tuple->nexthdr, l4_off, dir, &key->dport, NULL);\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_l4_offset_and_flags",
    "extract_l4_port",
    "ipv6_addr_copy"
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
static __always_inline int lb6_extract_key(struct __ctx_buff *ctx __maybe_unused,
					   struct ipv6_ct_tuple *tuple,
					   int l4_off __maybe_unused,
					   struct lb6_key *key,
					   struct csum_offset *csum_off,
					   enum ct_dir dir)
{
	union v6addr *addr;
	/* FIXME(brb): set after adding support for different L4 protocols in LB */
	key->proto = 0;
	addr = (dir == CT_INGRESS) ? &tuple->saddr : &tuple->daddr;
	ipv6_addr_copy(&key->address, addr);
	csum_l4_offset_and_flags(tuple->nexthdr, csum_off);

	return extract_l4_port(ctx, tuple->nexthdr, l4_off, dir, &key->dport,
			       NULL);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 518,
  "endLine": 541,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_src_range_ok",
  "developer_inline_comments": [
    {
      "start_line": 23,
      "end_line": 23,
      "text": "/* ENABLE_SRC_RANGE_CHECK */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " LB6_SRC_RANGE_MAP"
  ],
  "input": [
    "const struct lb6_service * svc __maybe_unused",
    " const union v6addr * saddr __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_src_range_ok (const struct lb6_service * svc __maybe_unused, const union v6addr * saddr __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_SRC_RANGE_CHECK\n",
    "    struct lb6_src_range_key key;\n",
    "    if (!lb6_svc_has_src_range_check (svc))\n",
    "        return true;\n",
    "    key = (typeof (key)) {\n",
    "        .lpm_key = {SRC_RANGE_STATIC_PREFIX (key),\n",
    "            {}},\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .addr = *saddr,};\n",
    "    if (map_lookup_elem (&LB6_SRC_RANGE_MAP, &key))\n",
    "        return true;\n",
    "    return false;\n",
    "\n",
    "#else\n",
    "    return true;\n",
    "\n",
    "#endif /* ENABLE_SRC_RANGE_CHECK */\n",
    "}\n"
  ],
  "called_function_list": [
    "lb6_svc_has_src_range_check",
    "SRC_RANGE_STATIC_PREFIX",
    "typeof"
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
bool lb6_src_range_ok(const struct lb6_service *svc __maybe_unused,
		      const union v6addr *saddr __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	struct lb6_src_range_key key;

	if (!lb6_svc_has_src_range_check(svc))
		return true;

	key = (typeof(key)) {
		.lpm_key = { SRC_RANGE_STATIC_PREFIX(key), {} },
		.rev_nat_id = svc->rev_nat_index,
		.addr = *saddr,
	};

	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
		return true;

	return false;
#else
	return true;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 543,
  "endLine": 551,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_to_lb4_service",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_to_lb4_service (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NAT_46X64\n",
    "    return svc->flags2 & SVC_FLAG_NAT_46X64;\n",
    "\n",
    "#else\n",
    "    return false;\n",
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
static __always_inline bool
lb6_to_lb4_service(const struct lb6_service *svc __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	return svc->flags2 & SVC_FLAG_NAT_46X64;
#else
	return false;
#endif
}

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
  "startLine": 553,
  "endLine": 573,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_lookup_service",
  "developer_inline_comments": [
    {
      "start_line": 12,
      "end_line": 12,
      "text": "/* Packets for L7 LB are redirected even when there are no backends. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  LB6_SERVICES_MAP_V2"
  ],
  "input": [
    "struct lb6_key *key",
    " const bool scope_switch"
  ],
  "output": "static__always_inlinestructlb6_service",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb6_service *lb6_lookup_service (struct lb6_key *key, const bool scope_switch)\n",
    "{\n",
    "    struct lb6_service *svc;\n",
    "    key->scope = LB_LOOKUP_SCOPE_EXT;\n",
    "    key->backend_slot = 0;\n",
    "    svc = map_lookup_elem (& LB6_SERVICES_MAP_V2, key);\n",
    "    if (svc) {\n",
    "        if (!scope_switch || !lb6_svc_is_local_scope (svc))\n",
    "            return (svc->count || lb6_svc_is_l7loadbalancer (svc)) ? svc : NULL;\n",
    "        key->scope = LB_LOOKUP_SCOPE_INT;\n",
    "        svc = map_lookup_elem (& LB6_SERVICES_MAP_V2, key);\n",
    "        if (svc && (svc->count || lb6_svc_is_l7loadbalancer (svc)))\n",
    "            return svc;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb6_svc_is_l7loadbalancer",
    "lb6_svc_is_local_scope"
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
struct lb6_service *lb6_lookup_service(struct lb6_key *key,
				       const bool scope_switch)
{
	struct lb6_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb6_svc_is_local_scope(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || lb6_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
		if (svc && (svc->count || lb6_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

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
  "startLine": 575,
  "endLine": 578,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_lookup_backend",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " LB6_BACKEND_MAP_V2"
  ],
  "input": [
    "__u32 backend_id"
  ],
  "output": "static__always_inlinestructlb6_backend",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb6_backend *__lb6_lookup_backend (__u32 backend_id)\n",
    "{\n",
    "    return map_lookup_elem (&LB6_BACKEND_MAP_V2, &backend_id);\n",
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
static __always_inline struct lb6_backend *__lb6_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB6_BACKEND_MAP_V2, &backend_id);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 580,
  "endLine": 590,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_lookup_backend",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinestructlb6_backend",
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
    "static __always_inline struct lb6_backend *lb6_lookup_backend (struct  __ctx_buff * ctx __maybe_unused, __u32 backend_id)\n",
    "{\n",
    "    struct lb6_backend *backend;\n",
    "    backend = __lb6_lookup_backend (backend_id);\n",
    "    if (!backend)\n",
    "        cilium_dbg_lb (ctx, DBG_LB6_LOOKUP_BACKEND_FAIL, backend_id, 0);\n",
    "    return backend;\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_lb",
    "__lb6_lookup_backend"
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
static __always_inline struct lb6_backend *
lb6_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u32 backend_id)
{
	struct lb6_backend *backend;

	backend = __lb6_lookup_backend(backend_id);
	if (!backend)
		cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_FAIL, backend_id, 0);

	return backend;
}

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
  "startLine": 592,
  "endLine": 596,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_lookup_backend_slot",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " LB6_SERVICES_MAP_V2"
  ],
  "input": [
    "struct lb6_key *key"
  ],
  "output": "static__always_inlinestructlb6_service",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb6_service *__lb6_lookup_backend_slot (struct lb6_key *key)\n",
    "{\n",
    "    return map_lookup_elem (&LB6_SERVICES_MAP_V2, key);\n",
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
struct lb6_service *__lb6_lookup_backend_slot(struct lb6_key *key)
{
	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 598,
  "endLine": 613,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_lookup_backend_slot",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct lb6_key *key",
    " __u16 slot"
  ],
  "output": "static__always_inlinestructlb6_service",
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
    "static __always_inline struct lb6_service *lb6_lookup_backend_slot (struct  __ctx_buff * ctx __maybe_unused, struct lb6_key *key, __u16 slot)\n",
    "{\n",
    "    struct lb6_service *svc;\n",
    "    key->backend_slot = slot;\n",
    "    cilium_dbg_lb (ctx, DBG_LB6_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);\n",
    "    svc = __lb6_lookup_backend_slot (key);\n",
    "    if (svc)\n",
    "        return svc;\n",
    "    cilium_dbg_lb (ctx, DBG_LB6_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_lb",
    "__lb6_lookup_backend_slot"
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
struct lb6_service *lb6_lookup_backend_slot(struct __ctx_buff *ctx __maybe_unused,
					    struct lb6_key *key, __u16 slot)
{
	struct lb6_service *svc;

	key->backend_slot = slot;
	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);
	svc = __lb6_lookup_backend_slot(key);
	if (svc)
		return svc;

	cilium_dbg_lb(ctx, DBG_LB6_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);

	return NULL;
}

/* Backend slot 0 is always reserved for the service frontend. */
#if LB_SELECTION == LB_SELECTION_RANDOM
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 617,
  "endLine": 627,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_select_backend_id",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* Backend slot 0 is always reserved for the service frontend. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct lb6_key *key",
    " const struct ipv6_ct_tuple * tuple __maybe_unused",
    " const struct lb6_service *svc"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb6_select_backend_id (struct  __ctx_buff *ctx, struct lb6_key *key, const struct ipv6_ct_tuple * tuple __maybe_unused, const struct lb6_service *svc)\n",
    "{\n",
    "    __u16 slot = (get_prandom_u32 () % svc->count) + 1;\n",
    "    struct lb6_service *be = lb6_lookup_backend_slot (ctx, key, slot);\n",
    "    return be ? be->backend_id : 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "map_array_get_32",
    "lb6_lookup_backend_slot",
    "unlikely",
    "hash_from_tuple_v6"
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
static __always_inline __u32
lb6_select_backend_id(struct __ctx_buff *ctx,
		      struct lb6_key *key,
		      const struct ipv6_ct_tuple *tuple __maybe_unused,
		      const struct lb6_service *svc)
{
	__u16 slot = (get_prandom_u32() % svc->count) + 1;
	struct lb6_service *be = lb6_lookup_backend_slot(ctx, key, slot);

	return be ? be->backend_id : 0;
}
#elif LB_SELECTION == LB_SELECTION_MAGLEV
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
  "startLine": 629,
  "endLine": 649,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_select_backend_id",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  LB6_MAGLEV_MAP_OUTER",
    " maglev_lut"
  ],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct lb6_key * key __maybe_unused",
    " const struct ipv6_ct_tuple *tuple",
    " const struct lb6_service *svc"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u32 lb6_select_backend_id (struct  __ctx_buff * ctx __maybe_unused, struct lb6_key * key __maybe_unused, const struct ipv6_ct_tuple *tuple, const struct lb6_service *svc)\n",
    "{\n",
    "    __u32 zero = 0, index = svc->rev_nat_index;\n",
    "    __u32 *backend_ids;\n",
    "    void *maglev_lut;\n",
    "    maglev_lut = map_lookup_elem (& LB6_MAGLEV_MAP_OUTER, & index);\n",
    "    if (unlikely (!maglev_lut))\n",
    "        return 0;\n",
    "    backend_ids = map_lookup_elem (maglev_lut, & zero);\n",
    "    if (unlikely (!backend_ids))\n",
    "        return 0;\n",
    "    index = hash_from_tuple_v6 (tuple) % LB_MAGLEV_LUT_SIZE;\n",
    "    return map_array_get_32 (backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);\n",
    "}\n"
  ],
  "called_function_list": [
    "map_array_get_32",
    "lb6_lookup_backend_slot",
    "unlikely",
    "hash_from_tuple_v6"
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
static __always_inline __u32
lb6_select_backend_id(struct __ctx_buff *ctx __maybe_unused,
		      struct lb6_key *key __maybe_unused,
		      const struct ipv6_ct_tuple *tuple,
		      const struct lb6_service *svc)
{
	__u32 zero = 0, index = svc->rev_nat_index;
	__u32 *backend_ids;
	void *maglev_lut;

	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
	if (unlikely(!maglev_lut))
		return 0;

	backend_ids = map_lookup_elem(maglev_lut, &zero);
	if (unlikely(!backend_ids))
		return 0;

	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
        return map_array_get_32(backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 654,
  "endLine": 689,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_xlate",
  "developer_inline_comments": [
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* LB_SELECTION */"
    },
    {
      "start_line": 31,
      "end_line": 31,
      "text": "/* Port offsets for UDP and TCP are the same */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *new_dst",
    " __u8 nexthdr",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " const struct lb6_key *key",
    " const struct lb6_backend *backend",
    " const bool skip_l3_xlate"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int lb6_xlate (struct  __ctx_buff *ctx, const union v6addr *new_dst, __u8 nexthdr, int l3_off, int l4_off, struct csum_offset *csum_off, const struct lb6_key *key, const struct lb6_backend *backend, const bool skip_l3_xlate)\n",
    "{\n",
    "    if (skip_l3_xlate)\n",
    "        goto l4_xlate;\n",
    "    ipv6_store_daddr (ctx, new_dst->addr, l3_off);\n",
    "    if (csum_off) {\n",
    "        __be32 sum = csum_diff (key -> address.addr, 16, new_dst -> addr, 16, 0);\n",
    "        if (csum_l4_replace (ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "            return DROP_CSUM_L4;\n",
    "    }\n",
    "l4_xlate :\n",
    "    if (likely (backend->port) && key->dport != backend->port && (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {\n",
    "        __be16 tmp = backend->port;\n",
    "        int ret;\n",
    "        ret = l4_modify_port (ctx, l4_off, TCP_DPORT_OFF, csum_off, tmp, key -> dport);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "IS_ERR",
    "ipv6_store_daddr",
    "csum_l4_replace",
    "likely"
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
static __always_inline int lb6_xlate(struct __ctx_buff *ctx,
				     const union v6addr *new_dst, __u8 nexthdr,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     const struct lb6_key *key,
				     const struct lb6_backend *backend,
				     const bool skip_l3_xlate)
{
	if (skip_l3_xlate)
		goto l4_xlate;

	ipv6_store_daddr(ctx, new_dst->addr, l3_off);
	if (csum_off) {
		__be32 sum = csum_diff(key->address.addr, 16, new_dst->addr,
				       16, 0);

		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	if (likely(backend->port) && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP)) {
		__be16 tmp = backend->port;
		int ret;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off,
				     tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
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
  "startLine": 692,
  "endLine": 728,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_affinity_backend_id",
  "developer_inline_comments": [],
  "updateMaps": [
    " LB6_AFFINITY_MAP"
  ],
  "readMaps": [
    " LB_AFFINITY_MATCH_MAP",
    "  LB6_AFFINITY_MAP"
  ],
  "input": [
    "const struct lb6_service *svc",
    " bool netns_cookie",
    " union lb6_affinity_client_id *id"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem",
    "map_delete_elem"
  ],
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
    "sched_cls",
    "sk_skb",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __always_inline __u32 __lb6_affinity_backend_id (const struct lb6_service *svc, bool netns_cookie, union lb6_affinity_client_id *id)\n",
    "{\n",
    "    struct lb6_affinity_key key = {\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .netns_cookie = netns_cookie,}\n",
    "    ;\n",
    "    struct lb_affinity_val *val;\n",
    "    ipv6_addr_copy (&key.client_id.client_ip, &id->client_ip);\n",
    "    val = map_lookup_elem (& LB6_AFFINITY_MAP, & key);\n",
    "    if (val != NULL) {\n",
    "        __u32 now = bpf_mono_now ();\n",
    "        struct lb_affinity_match match = {\n",
    "            .rev_nat_id = svc->rev_nat_index,\n",
    "            .backend_id = val->backend_id,}\n",
    "        ;\n",
    "        if (READ_ONCE (val->last_used) + bpf_sec_to_mono (svc->affinity_timeout) <= now) {\n",
    "            map_delete_elem (&LB6_AFFINITY_MAP, &key);\n",
    "            return 0;\n",
    "        }\n",
    "        if (!map_lookup_elem (&LB_AFFINITY_MATCH_MAP, &match)) {\n",
    "            map_delete_elem (&LB6_AFFINITY_MAP, &key);\n",
    "            return 0;\n",
    "        }\n",
    "        WRITE_ONCE (val->last_used, now);\n",
    "        return val->backend_id;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_mono_now",
    "bpf_sec_to_mono",
    "WRITE_ONCE",
    "READ_ONCE",
    "ipv6_addr_copy"
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
static __always_inline __u32
__lb6_affinity_backend_id(const struct lb6_service *svc, bool netns_cookie,
			  union lb6_affinity_client_id *id)
{
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};
	struct lb_affinity_val *val;

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	val = map_lookup_elem(&LB6_AFFINITY_MAP, &key);
	if (val != NULL) {
		__u32 now = bpf_mono_now();
		struct lb_affinity_match match = {
			.rev_nat_id	= svc->rev_nat_index,
			.backend_id	= val->backend_id,
		};

		if (READ_ONCE(val->last_used) +
		    bpf_sec_to_mono(svc->affinity_timeout) <= now) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
			map_delete_elem(&LB6_AFFINITY_MAP, &key);
			return 0;
		}

		WRITE_ONCE(val->last_used, now);
		return val->backend_id;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 730,
  "endLine": 735,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_affinity_backend_id_by_addr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc",
    " union lb6_affinity_client_id *id"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb6_affinity_backend_id_by_addr (const struct lb6_service *svc, union lb6_affinity_client_id *id)\n",
    "{\n",
    "    return __lb6_affinity_backend_id (svc, false, id);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb6_affinity_backend_id"
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
static __always_inline __u32
lb6_affinity_backend_id_by_addr(const struct lb6_service *svc,
				union lb6_affinity_client_id *id)
{
	return __lb6_affinity_backend_id(svc, false, id);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 737,
  "endLine": 754,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_update_affinity",
  "developer_inline_comments": [],
  "updateMaps": [
    " LB6_AFFINITY_MAP"
  ],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc",
    " bool netns_cookie",
    " union lb6_affinity_client_id *id",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "map_update_elem"
  ],
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
    "static __always_inline void __lb6_update_affinity (const struct lb6_service *svc, bool netns_cookie, union lb6_affinity_client_id *id, __u32 backend_id)\n",
    "{\n",
    "    __u32 now = bpf_mono_now ();\n",
    "    struct lb6_affinity_key key = {\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .netns_cookie = netns_cookie,}\n",
    "    ;\n",
    "    struct lb_affinity_val val = {\n",
    "        .backend_id = backend_id,\n",
    "        .last_used = now,}\n",
    "    ;\n",
    "    ipv6_addr_copy (&key.client_id.client_ip, &id->client_ip);\n",
    "    map_update_elem (&LB6_AFFINITY_MAP, &key, &val, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_mono_now",
    "ipv6_addr_copy"
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
static __always_inline void
__lb6_update_affinity(const struct lb6_service *svc, bool netns_cookie,
		      union lb6_affinity_client_id *id, __u32 backend_id)
{
	__u32 now = bpf_mono_now();
	struct lb6_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
	};
	struct lb_affinity_val val = {
		.backend_id	= backend_id,
		.last_used	= now,
	};

	ipv6_addr_copy(&key.client_id.client_ip, &id->client_ip);

	map_update_elem(&LB6_AFFINITY_MAP, &key, &val, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 756,
  "endLine": 761,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_update_affinity_by_addr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service *svc",
    " union lb6_affinity_client_id *id",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb6_update_affinity_by_addr (const struct lb6_service *svc, union lb6_affinity_client_id *id, __u32 backend_id)\n",
    "{\n",
    "    __lb6_update_affinity (svc, false, id, backend_id);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb6_update_affinity"
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
static __always_inline void
lb6_update_affinity_by_addr(const struct lb6_service *svc,
			    union lb6_affinity_client_id *id, __u32 backend_id)
{
	__lb6_update_affinity(svc, false, id, backend_id);
}
#endif /* ENABLE_SESSION_AFFINITY */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 764,
  "endLine": 773,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_affinity_backend_id_by_netns",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused",
    " union lb6_affinity_client_id * id __maybe_unused"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb6_affinity_backend_id_by_netns (const struct lb6_service * svc __maybe_unused, union lb6_affinity_client_id * id __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(ENABLE_SESSION_AFFINITY)\n",
    "    return __lb6_affinity_backend_id (svc, true, id);\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "__lb6_affinity_backend_id"
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
static __always_inline __u32
lb6_affinity_backend_id_by_netns(const struct lb6_service *svc __maybe_unused,
				 union lb6_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
	return __lb6_affinity_backend_id(svc, true, id);
#else
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 775,
  "endLine": 783,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_update_affinity_by_netns",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused",
    " union lb6_affinity_client_id * id __maybe_unused",
    " __u32 backend_id __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb6_update_affinity_by_netns (const struct lb6_service * svc __maybe_unused, union lb6_affinity_client_id * id __maybe_unused, __u32 backend_id __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(ENABLE_SESSION_AFFINITY)\n",
    "    __lb6_update_affinity (svc, true, id, backend_id);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "__lb6_update_affinity"
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
static __always_inline void
lb6_update_affinity_by_netns(const struct lb6_service *svc __maybe_unused,
			     union lb6_affinity_client_id *id __maybe_unused,
			     __u32 backend_id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
	__lb6_update_affinity(svc, true, id, backend_id);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 785,
  "endLine": 799,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_to_lb4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " const struct ipv6hdr * ip6 __maybe_unused"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int lb6_to_lb4 (struct  __ctx_buff * ctx __maybe_unused, const struct ipv6hdr * ip6 __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NAT_46X64\n",
    "    __be32 src4, dst4;\n",
    "    build_v4_from_v6 ((const union v6addr *) &ip6->saddr, &src4);\n",
    "    build_v4_from_v6 ((const union v6addr *) &ip6->daddr, &dst4);\n",
    "    return ipv6_to_ipv4 (ctx, src4, dst4);\n",
    "\n",
    "#else\n",
    "    return DROP_NAT_46X64_DISABLED;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "build_v4_from_v6",
    "ipv6_to_ipv4"
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
static __always_inline int
lb6_to_lb4(struct __ctx_buff *ctx __maybe_unused,
	   const struct ipv6hdr *ip6 __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	__be32 src4, dst4;

	build_v4_from_v6((const union v6addr *)&ip6->saddr, &src4);
	build_v4_from_v6((const union v6addr *)&ip6->daddr, &dst4);

	return ipv6_to_ipv4(ctx, src4, dst4);
#else
	return DROP_NAT_46X64_DISABLED;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 801,
  "endLine": 926,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_local",
  "developer_inline_comments": [
    {
      "start_line": 10,
      "end_line": 10,
      "text": "/* Deliberately ignored; regular CT will determine monitoring. */"
    },
    {
      "start_line": 22,
      "end_line": 22,
      "text": "/* See lb4_local comments re svc endpoint lookup process */"
    },
    {
      "start_line": 47,
      "end_line": 49,
      "text": "/* Fail closed, if the conntrack entry create fails drop\n\t\t * service lookup.\n\t\t */"
    },
    {
      "start_line": 57,
      "end_line": 57,
      "text": "/* See lb4_local comment */"
    },
    {
      "start_line": 67,
      "end_line": 67,
      "text": "/* See lb4_local comment */"
    },
    {
      "start_line": 85,
      "end_line": 88,
      "text": "/* If the lookup fails it means the user deleted the backend out from\n\t * underneath us. To resolve this fall back to hash. If this is a TCP\n\t * session we are likely to get a TCP RST.\n\t */"
    },
    {
      "start_line": 91,
      "end_line": 93,
      "text": "/* Drain existing connections, but redirect new ones to only\n\t\t * active backends.\n\t\t */"
    },
    {
      "start_line": 108,
      "end_line": 110,
      "text": "/* Restore flags so that SERVICE flag is only used in used when the\n\t * service lookup happens and future lookups use EGRESS or INGRESS.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *map",
    " struct  __ctx_buff *ctx",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct lb6_key *key",
    " struct ipv6_ct_tuple *tuple",
    " const struct lb6_service *svc",
    " struct ct_state *state",
    " const bool skip_l3_xlate"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int lb6_local (const void *map, struct  __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct lb6_key *key, struct ipv6_ct_tuple *tuple, const struct lb6_service *svc, struct ct_state *state, const bool skip_l3_xlate)\n",
    "{\n",
    "    __u32 monitor;\n",
    "    union v6addr *addr;\n",
    "    __u8 flags = tuple->flags;\n",
    "    struct lb6_backend *backend;\n",
    "    __u32 backend_id = 0;\n",
    "    int ret;\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "    union lb6_affinity_client_id client_id;\n",
    "    ipv6_addr_copy (&client_id.client_ip, &tuple->saddr);\n",
    "\n",
    "#endif\n",
    "    ret = ct_lookup6 (map, tuple, ctx, l4_off, CT_SERVICE, state, & monitor);\n",
    "    switch (ret) {\n",
    "    case CT_NEW :\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "        if (lb6_svc_is_affinity (svc)) {\n",
    "            backend_id = lb6_affinity_backend_id_by_addr (svc, & client_id);\n",
    "            if (backend_id != 0) {\n",
    "                backend = lb6_lookup_backend (ctx, backend_id);\n",
    "                if (backend == NULL)\n",
    "                    backend_id = 0;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        if (backend_id == 0) {\n",
    "            backend_id = lb6_select_backend_id (ctx, key, tuple, svc);\n",
    "            backend = lb6_lookup_backend (ctx, backend_id);\n",
    "            if (backend == NULL)\n",
    "                goto drop_no_service;\n",
    "        }\n",
    "        state->backend_id = backend_id;\n",
    "        state->rev_nat_index = svc->rev_nat_index;\n",
    "        ret = ct_create6 (map, NULL, tuple, ctx, CT_SERVICE, state, false, false);\n",
    "        if (IS_ERR (ret))\n",
    "            goto drop_no_service;\n",
    "        goto update_state;\n",
    "    case CT_REOPENED :\n",
    "    case CT_ESTABLISHED :\n",
    "    case CT_RELATED :\n",
    "    case CT_REPLY :\n",
    "        if (state->rev_nat_index == 0) {\n",
    "            state->rev_nat_index = svc->rev_nat_index;\n",
    "            ct_update6_rev_nat_index (map, tuple, state);\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        goto drop_no_service;\n",
    "    }\n",
    "    if (state->rev_nat_index != svc->rev_nat_index) {\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "        if (lb6_svc_is_affinity (svc))\n",
    "            backend_id = lb6_affinity_backend_id_by_addr (svc, &client_id);\n",
    "\n",
    "#endif\n",
    "        if (!backend_id) {\n",
    "            backend_id = lb6_select_backend_id (ctx, key, tuple, svc);\n",
    "            if (!backend_id)\n",
    "                goto drop_no_service;\n",
    "        }\n",
    "        state->backend_id = backend_id;\n",
    "        ct_update6_backend_id (map, tuple, state);\n",
    "        state->rev_nat_index = svc->rev_nat_index;\n",
    "        ct_update6_rev_nat_index (map, tuple, state);\n",
    "    }\n",
    "    backend = lb6_lookup_backend (ctx, state -> backend_id);\n",
    "    if (unlikely (!backend || backend->flags != BE_STATE_ACTIVE)) {\n",
    "        if (backend && !state->syn)\n",
    "            goto update_state;\n",
    "        key->backend_slot = 0;\n",
    "        svc = lb6_lookup_service (key, false);\n",
    "        if (!svc)\n",
    "            goto drop_no_service;\n",
    "        backend_id = lb6_select_backend_id (ctx, key, tuple, svc);\n",
    "        backend = lb6_lookup_backend (ctx, backend_id);\n",
    "        if (!backend)\n",
    "            goto drop_no_service;\n",
    "        state->backend_id = backend_id;\n",
    "        ct_update6_backend_id (map, tuple, state);\n",
    "    }\n",
    "update_state :\n",
    "    tuple->flags = flags;\n",
    "    ipv6_addr_copy (&tuple->daddr, &backend->address);\n",
    "    addr = &tuple->daddr;\n",
    "    state->rev_nat_index = svc->rev_nat_index;\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "    if (lb6_svc_is_affinity (svc))\n",
    "        lb6_update_affinity_by_addr (svc, &client_id, state->backend_id);\n",
    "\n",
    "#endif\n",
    "    return lb_skip_l4_dnat () ? CTX_ACT_OK : lb6_xlate (ctx, addr, tuple->nexthdr, l3_off, l4_off, csum_off, key, backend, skip_l3_xlate);\n",
    "drop_no_service :\n",
    "    tuple->flags = flags;\n",
    "    return DROP_NO_SERVICE;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb6_lookup_service",
    "lb6_svc_is_affinity",
    "lb6_lookup_backend",
    "ct_lookup6",
    "IS_ERR",
    "ct_update6_rev_nat_index",
    "unlikely",
    "lb_skip_l4_dnat",
    "lb6_select_backend_id",
    "ipv6_addr_copy",
    "ct_update6_backend_id",
    "ct_create6",
    "lb6_update_affinity_by_addr",
    "lb6_affinity_backend_id_by_addr",
    "lb6_xlate"
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
static __always_inline int lb6_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb6_key *key,
				     struct ipv6_ct_tuple *tuple,
				     const struct lb6_service *svc,
				     struct ct_state *state,
				     const bool skip_l3_xlate)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	union v6addr *addr;
	__u8 flags = tuple->flags;
	struct lb6_backend *backend;
	__u32 backend_id = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb6_affinity_client_id client_id;

	ipv6_addr_copy(&client_id.client_ip, &tuple->saddr);
#endif

	/* See lb4_local comments re svc endpoint lookup process */
	ret = ct_lookup6(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch (ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (lb6_svc_is_affinity(svc)) {
			backend_id = lb6_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend = lb6_lookup_backend(ctx, backend_id);
				if (backend == NULL)
					backend_id = 0;
			}
		}
#endif
		if (backend_id == 0) {
			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			backend = lb6_lookup_backend(ctx, backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create6(map, NULL, tuple, ctx, CT_SERVICE, state, false, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_no_service;
		goto update_state;
	case CT_REOPENED:
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		/* See lb4_local comment */
		if (state->rev_nat_index == 0) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update6_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	/* See lb4_local comment */
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (lb6_svc_is_affinity(svc))
			backend_id = lb6_affinity_backend_id_by_addr(svc,
								     &client_id);
#endif
		if (!backend_id) {
			backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
			if (!backend_id)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		ct_update6_backend_id(map, tuple, state);
		state->rev_nat_index = svc->rev_nat_index;
		ct_update6_rev_nat_index(map, tuple, state);
	}
	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	backend = lb6_lookup_backend(ctx, state->backend_id);
	if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
		/* Drain existing connections, but redirect new ones to only
		 * active backends.
		 */
		if (backend && !state->syn)
			goto update_state;
		key->backend_slot = 0;
		svc = lb6_lookup_service(key, false);
		if (!svc)
			goto drop_no_service;
		backend_id = lb6_select_backend_id(ctx, key, tuple, svc);
		backend = lb6_lookup_backend(ctx, backend_id);
		if (!backend)
			goto drop_no_service;
		state->backend_id = backend_id;
		ct_update6_backend_id(map, tuple, state);
	}
update_state:
	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	ipv6_addr_copy(&tuple->daddr, &backend->address);
	addr = &tuple->daddr;
	state->rev_nat_index = svc->rev_nat_index;
#ifdef ENABLE_SESSION_AFFINITY
	if (lb6_svc_is_affinity(svc))
		lb6_update_affinity_by_addr(svc, &client_id,
					    state->backend_id);
#endif
	return lb_skip_l4_dnat() ? CTX_ACT_OK :
	       lb6_xlate(ctx, addr, tuple->nexthdr, l3_off, l4_off,
			 csum_off, key, backend, skip_l3_xlate);
drop_no_service:
	tuple->flags = flags;
	return DROP_NO_SERVICE;
}

/* lb6_ctx_store_state() stores per packet load balancing state to be picked
 * up on the continuation tail call.
 * Note that the IP headers are already xlated and the tuple is re-initialized
 * from the xlated headers before restoring state.
 * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We
 * lose the updated tuple daddr in that case.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 935,
  "endLine": 942,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_ctx_store_state",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 7,
      "text": "/* lb6_ctx_store_state() stores per packet load balancing state to be picked\n * up on the continuation tail call.\n * Note that the IP headers are already xlated and the tuple is re-initialized\n * from the xlated headers before restoring state.\n * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We\n * lose the updated tuple daddr in that case.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ct_state *state",
    " __u16 proxy_port"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb6_ctx_store_state (struct  __ctx_buff *ctx, const struct ct_state *state, __u16 proxy_port)\n",
    "{\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, (__u32) proxy_port << 16);\n",
    "    ctx_store_meta (ctx, CB_BACKEND_ID, state->backend_id);\n",
    "    ctx_store_meta (ctx, CB_CT_STATE, (__u32) state->rev_nat_index);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta"
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
static __always_inline void lb6_ctx_store_state(struct __ctx_buff *ctx,
						const struct ct_state *state,
					       __u16 proxy_port)
{
	ctx_store_meta(ctx, CB_PROXY_MAGIC, (__u32)proxy_port << 16);
	ctx_store_meta(ctx, CB_BACKEND_ID, state->backend_id);
	ctx_store_meta(ctx, CB_CT_STATE, (__u32)state->rev_nat_index);
}

/* lb6_ctx_restore_state() restores per packet load balancing state from the
 * previous tail call.
 * tuple->flags does not need to be restored, as it will be reinitialized from
 * the packet.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 949,
  "endLine": 965,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_ctx_restore_state",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "/* lb6_ctx_restore_state() restores per packet load balancing state from the\n * previous tail call.\n * tuple->flags does not need to be restored, as it will be reinitialized from\n * the packet.\n */"
    },
    {
      "start_line": 11,
      "end_line": 11,
      "text": "/* Clear to not leak state to later stages of the datapath. */"
    },
    {
      "start_line": 14,
      "end_line": 14,
      "text": "/* No loopback support for IPv6, see lb6_local() above. */"
    },
    {
      "start_line": 17,
      "end_line": 17,
      "text": "/* Must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ct_state *state",
    " __u16 *proxy_port"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb6_ctx_restore_state (struct  __ctx_buff *ctx, struct ct_state *state, __u16 *proxy_port)\n",
    "{\n",
    "    state->rev_nat_index = (__u16) ctx_load_meta (ctx, CB_CT_STATE);\n",
    "    ctx_store_meta (ctx, CB_CT_STATE, 0);\n",
    "    state->backend_id = ctx_load_meta (ctx, CB_BACKEND_ID);\n",
    "    ctx_store_meta (ctx, CB_BACKEND_ID, 0);\n",
    "    *proxy_port = ctx_load_meta (ctx, CB_PROXY_MAGIC) >> 16;\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta",
    "ctx_load_meta"
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
static __always_inline void lb6_ctx_restore_state(struct __ctx_buff *ctx,
						  struct ct_state *state,
						 __u16 *proxy_port)
{
	state->rev_nat_index = (__u16)ctx_load_meta(ctx, CB_CT_STATE);
	/* Clear to not leak state to later stages of the datapath. */
	ctx_store_meta(ctx, CB_CT_STATE, 0);

	/* No loopback support for IPv6, see lb6_local() above. */

	state->backend_id = ctx_load_meta(ctx, CB_BACKEND_ID);
	/* Must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */
	ctx_store_meta(ctx, CB_BACKEND_ID, 0);

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
}

#else

/* Stubs for v4-in-v6 socket cgroup hook case when only v4 is enabled to avoid
 * additional map management.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 972,
  "endLine": 977,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_lookup_service",
  "developer_inline_comments": [
    {
      "start_line": 3,
      "end_line": 5,
      "text": "/* Stubs for v4-in-v6 socket cgroup hook case when only v4 is enabled to avoid\n * additional map management.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb6_key * key __maybe_unused",
    " const bool scope_switch __maybe_unused"
  ],
  "output": "static__always_inlinestructlb6_service",
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
    "static __always_inline struct lb6_service *lb6_lookup_service (struct lb6_key * key __maybe_unused, const bool scope_switch __maybe_unused)\n",
    "{\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb6_svc_is_l7loadbalancer",
    "lb6_svc_is_local_scope"
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
struct lb6_service *lb6_lookup_service(struct lb6_key *key __maybe_unused,
				       const bool scope_switch __maybe_unused)
{
	return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 979,
  "endLine": 983,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_lookup_backend_slot",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb6_key * key __maybe_unused"
  ],
  "output": "static__always_inlinestructlb6_service",
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
    "static __always_inline struct lb6_service *__lb6_lookup_backend_slot (struct lb6_key * key __maybe_unused)\n",
    "{\n",
    "    return NULL;\n",
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
struct lb6_service *__lb6_lookup_backend_slot(struct lb6_key *key __maybe_unused)
{
	return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 985,
  "endLine": 989,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb6_lookup_backend",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 backend_id __maybe_unused"
  ],
  "output": "static__always_inlinestructlb6_backend",
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
    "static __always_inline struct lb6_backend *__lb6_lookup_backend (__u16 backend_id __maybe_unused)\n",
    "{\n",
    "    return NULL;\n",
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
static __always_inline struct lb6_backend *
__lb6_lookup_backend(__u16 backend_id __maybe_unused)
{
	return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 991,
  "endLine": 995,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb6_to_lb4_service",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb6_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb6_to_lb4_service (const struct lb6_service * svc __maybe_unused)\n",
    "{\n",
    "    return false;\n",
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
static __always_inline bool
lb6_to_lb4_service(const struct lb6_service *svc __maybe_unused)
{
	return false;
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_IPV4
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 999,
  "endLine": 1066,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb4_rev_nat",
  "developer_inline_comments": [
    {
      "start_line": 32,
      "end_line": 37,
      "text": "/* The packet was looped back to the sending endpoint on the\n\t\t * forward service translation. This implies that the original\n\t\t * source address of the packet is the source address of the\n\t\t * current packet. We therefore need to make the current source\n\t\t * address the new destination address.\n\t\t */"
    },
    {
      "start_line": 52,
      "end_line": 52,
      "text": "/* Update the tuple address which is representing the destination address */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct ipv4_ct_tuple *tuple",
    " int flags",
    " const struct lb4_reverse_nat *nat",
    " const struct ct_state *ct_state",
    " bool has_l4_header"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "lwt_out",
    "lwt_seg6local",
    "sched_act",
    "sched_cls",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int __lb4_rev_nat (struct  __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct ipv4_ct_tuple *tuple, int flags, const struct lb4_reverse_nat *nat, const struct ct_state *ct_state, bool has_l4_header)\n",
    "{\n",
    "    __be32 old_sip, new_sip, sum = 0;\n",
    "    int ret;\n",
    "    cilium_dbg_lb (ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);\n",
    "    if (nat->port && has_l4_header) {\n",
    "        ret = reverse_map_l4_port (ctx, tuple -> nexthdr, nat -> port, l4_off, csum_off);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    if (flags & REV_NAT_F_TUPLE_SADDR) {\n",
    "        old_sip = tuple->saddr;\n",
    "        tuple->saddr = new_sip = nat->address;\n",
    "    }\n",
    "    else {\n",
    "        ret = ctx_load_bytes (ctx, l3_off + offsetof (struct iphdr, saddr), & old_sip, 4);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        new_sip = nat->address;\n",
    "    }\n",
    "    if (ct_state->loopback) {\n",
    "        __be32 old_dip;\n",
    "        ret = ctx_load_bytes (ctx, l3_off + offsetof (struct iphdr, daddr), & old_dip, 4);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "        cilium_dbg_lb (ctx, DBG_LB4_LOOPBACK_SNAT_REV, old_dip, old_sip);\n",
    "        ret = ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, daddr), & old_sip, 4, 0);\n",
    "        if (IS_ERR (ret))\n",
    "            return DROP_WRITE_ERROR;\n",
    "        sum = csum_diff (& old_dip, 4, & old_sip, 4, 0);\n",
    "        tuple->saddr = old_sip;\n",
    "    }\n",
    "    ret = ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, saddr), & new_sip, 4, 0);\n",
    "    if (IS_ERR (ret))\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (& old_sip, 4, & new_sip, 4, sum);\n",
    "    if (l3_csum_replace (ctx, l3_off + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    if (csum_off->offset && csum_l4_replace (ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "IS_ERR",
    "ctx_store_bytes",
    "offsetof",
    "csum_l4_replace",
    "ctx_load_bytes",
    "cilium_dbg_lb",
    "reverse_map_l4_port"
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
static __always_inline int __lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
					 struct csum_offset *csum_off,
					 struct ipv4_ct_tuple *tuple, int flags,
					 const struct lb4_reverse_nat *nat,
					 const struct ct_state *ct_state, bool has_l4_header)
{
	__be32 old_sip, new_sip, sum = 0;
	int ret;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT, nat->address, nat->port);

	if (nat->port && has_l4_header) {
		ret = reverse_map_l4_port(ctx, tuple->nexthdr, nat->port, l4_off, csum_off);
		if (IS_ERR(ret))
			return ret;
	}

	if (flags & REV_NAT_F_TUPLE_SADDR) {
		old_sip = tuple->saddr;
		tuple->saddr = new_sip = nat->address;
	} else {
		ret = ctx_load_bytes(ctx, l3_off + offsetof(struct iphdr, saddr), &old_sip, 4);
		if (IS_ERR(ret))
			return ret;

		new_sip = nat->address;
	}

	if (ct_state->loopback) {
		/* The packet was looped back to the sending endpoint on the
		 * forward service translation. This implies that the original
		 * source address of the packet is the source address of the
		 * current packet. We therefore need to make the current source
		 * address the new destination address.
		 */
		__be32 old_dip;

		ret = ctx_load_bytes(ctx, l3_off + offsetof(struct iphdr, daddr), &old_dip, 4);
		if (IS_ERR(ret))
			return ret;

		cilium_dbg_lb(ctx, DBG_LB4_LOOPBACK_SNAT_REV, old_dip, old_sip);

		ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, daddr), &old_sip, 4, 0);
		if (IS_ERR(ret))
			return DROP_WRITE_ERROR;

		sum = csum_diff(&old_dip, 4, &old_sip, 4, 0);

		/* Update the tuple address which is representing the destination address */
		tuple->saddr = old_sip;
	}

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
			      &new_sip, 4, 0);
	if (IS_ERR(ret))
		return DROP_WRITE_ERROR;

	sum = csum_diff(&old_sip, 4, &new_sip, 4, sum);
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check), 0, sum, 0) < 0)
		return DROP_CSUM_L3;

	if (csum_off->offset &&
	    csum_l4_replace(ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;

	return 0;
}


/** Perform IPv4 reverse NAT based on reverse NAT index
 * @arg ctx		packet
 * @arg l3_off		offset to L3
 * @arg l4_off		offset to L4
 * @arg csum_off	offset to L4 checksum field
 * @arg csum_flags	checksum flags
 * @arg index		reverse NAT index
 * @arg tuple		tuple
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
  "startLine": 1078,
  "endLine": 1092,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_rev_nat",
  "developer_inline_comments": [
    {
      "start_line": 2,
      "end_line": 10,
      "text": "/** Perform IPv4 reverse NAT based on reverse NAT index\n * @arg ctx\t\tpacket\n * @arg l3_off\t\toffset to L3\n * @arg l4_off\t\toffset to L4\n * @arg csum_off\toffset to L4 checksum field\n * @arg csum_flags\tchecksum flags\n * @arg index\t\treverse NAT index\n * @arg tuple\t\ttuple\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  LB4_REVERSE_NAT_MAP"
  ],
  "input": [
    "struct  __ctx_buff *ctx",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct ct_state *ct_state",
    " struct ipv4_ct_tuple *tuple",
    " int flags",
    " bool has_l4_header"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline int lb4_rev_nat (struct  __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct ct_state *ct_state, struct ipv4_ct_tuple *tuple, int flags, bool has_l4_header)\n",
    "{\n",
    "    struct lb4_reverse_nat *nat;\n",
    "    cilium_dbg_lb (ctx, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);\n",
    "    nat = map_lookup_elem (& LB4_REVERSE_NAT_MAP, & ct_state -> rev_nat_index);\n",
    "    if (nat == NULL)\n",
    "        return 0;\n",
    "    return __lb4_rev_nat (ctx, l3_off, l4_off, csum_off, tuple, flags, nat, ct_state, has_l4_header);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_lb",
    "__lb4_rev_nat"
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
static __always_inline int lb4_rev_nat(struct __ctx_buff *ctx, int l3_off, int l4_off,
				       struct csum_offset *csum_off,
				       struct ct_state *ct_state,
				       struct ipv4_ct_tuple *tuple, int flags, bool has_l4_header)
{
	struct lb4_reverse_nat *nat;

	cilium_dbg_lb(ctx, DBG_LB4_REVERSE_NAT_LOOKUP, ct_state->rev_nat_index, 0);
	nat = map_lookup_elem(&LB4_REVERSE_NAT_MAP, &ct_state->rev_nat_index);
	if (nat == NULL)
		return 0;

	return __lb4_rev_nat(ctx, l3_off, l4_off, csum_off, tuple, flags, nat,
			     ct_state, has_l4_header);
}

/** Extract IPv4 LB key from packet
 * @arg ctx		Packet
 * @arg ip4		Pointer to L3 header
 * @arg l4_off		Offset to L4 header
 * @arg key		Pointer to store LB key in
 * @arg csum_off	Pointer to store L4 checksum field offset  in
 * @arg dir		Flow direction
 *
 * Returns:
 *   - CTX_ACT_OK on successful extraction
 *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)
 *   - Negative error code
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1107,
  "endLine": 1121,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_extract_key",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 13,
      "text": "/** Extract IPv4 LB key from packet\n * @arg ctx\t\tPacket\n * @arg ip4\t\tPointer to L3 header\n * @arg l4_off\t\tOffset to L4 header\n * @arg key\t\tPointer to store LB key in\n * @arg csum_off\tPointer to store L4 checksum field offset  in\n * @arg dir\t\tFlow direction\n *\n * Returns:\n *   - CTX_ACT_OK on successful extraction\n *   - DROP_UNKNOWN_L4 if packet should be ignore (sent to stack)\n *   - Negative error code\n */"
    },
    {
      "start_line": 21,
      "end_line": 21,
      "text": "/* FIXME: set after adding support for different L4 protocols in LB */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct iphdr *ip4",
    " int l4_off __maybe_unused",
    " struct lb4_key *key",
    " struct csum_offset *csum_off",
    " enum ct_dir dir"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int lb4_extract_key (struct  __ctx_buff * ctx __maybe_unused, struct iphdr *ip4, int l4_off __maybe_unused, struct lb4_key *key, struct csum_offset *csum_off, enum ct_dir dir)\n",
    "{\n",
    "    key->proto = 0;\n",
    "    key->address = (dir == CT_INGRESS) ? ip4->saddr : ip4->daddr;\n",
    "    if (ipv4_has_l4_header (ip4))\n",
    "        csum_l4_offset_and_flags (ip4->protocol, csum_off);\n",
    "    return extract_l4_port (ctx, ip4->protocol, l4_off, dir, &key->dport, ip4);\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_has_l4_header",
    "csum_l4_offset_and_flags",
    "extract_l4_port"
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
static __always_inline int lb4_extract_key(struct __ctx_buff *ctx __maybe_unused,
					   struct iphdr *ip4,
					   int l4_off __maybe_unused,
					   struct lb4_key *key,
					   struct csum_offset *csum_off,
					   enum ct_dir dir)
{
	/* FIXME: set after adding support for different L4 protocols in LB */
	key->proto = 0;
	key->address = (dir == CT_INGRESS) ? ip4->saddr : ip4->daddr;
	if (ipv4_has_l4_header(ip4))
		csum_l4_offset_and_flags(ip4->protocol, csum_off);

	return extract_l4_port(ctx, ip4->protocol, l4_off, dir, &key->dport, ip4);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1123,
  "endLine": 1146,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_src_range_ok",
  "developer_inline_comments": [
    {
      "start_line": 23,
      "end_line": 23,
      "text": "/* ENABLE_SRC_RANGE_CHECK */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " LB4_SRC_RANGE_MAP"
  ],
  "input": [
    "const struct lb4_service * svc __maybe_unused",
    " __u32 saddr __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_src_range_ok (const struct lb4_service * svc __maybe_unused, __u32 saddr __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_SRC_RANGE_CHECK\n",
    "    struct lb4_src_range_key key;\n",
    "    if (!lb4_svc_has_src_range_check (svc))\n",
    "        return true;\n",
    "    key = (typeof (key)) {\n",
    "        .lpm_key = {SRC_RANGE_STATIC_PREFIX (key),\n",
    "            {}},\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .addr = saddr,};\n",
    "    if (map_lookup_elem (&LB4_SRC_RANGE_MAP, &key))\n",
    "        return true;\n",
    "    return false;\n",
    "\n",
    "#else\n",
    "    return true;\n",
    "\n",
    "#endif /* ENABLE_SRC_RANGE_CHECK */\n",
    "}\n"
  ],
  "called_function_list": [
    "SRC_RANGE_STATIC_PREFIX",
    "lb4_svc_has_src_range_check",
    "typeof"
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
bool lb4_src_range_ok(const struct lb4_service *svc __maybe_unused,
		      __u32 saddr __maybe_unused)
{
#ifdef ENABLE_SRC_RANGE_CHECK
	struct lb4_src_range_key key;

	if (!lb4_svc_has_src_range_check(svc))
		return true;

	key = (typeof(key)) {
		.lpm_key = { SRC_RANGE_STATIC_PREFIX(key), {} },
		.rev_nat_id = svc->rev_nat_index,
		.addr = saddr,
	};

	if (map_lookup_elem(&LB4_SRC_RANGE_MAP, &key))
		return true;

	return false;
#else
	return true;
#endif /* ENABLE_SRC_RANGE_CHECK */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1148,
  "endLine": 1164,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_populate_ports",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv4_ct_tuple *tuple",
    " int off"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int lb4_populate_ports (struct  __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, int off)\n",
    "{\n",
    "    if (tuple->nexthdr == IPPROTO_TCP || tuple->nexthdr == IPPROTO_UDP) {\n",
    "        struct {\n",
    "            __be16 sport;\n",
    "            __be16 dport;\n",
    "        } l4hdr;\n",
    "\n",
    "        if (ctx_load_bytes (ctx, off, &l4hdr, sizeof (l4hdr)) < 0)\n",
    "            return -EFAULT;\n",
    "        tuple->sport = l4hdr.sport;\n",
    "        tuple->dport = l4hdr.dport;\n",
    "        return 0;\n",
    "    }\n",
    "    return -ENOTSUP;\n",
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
static __always_inline int
lb4_populate_ports(struct __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, int off)
{
	if (tuple->nexthdr == IPPROTO_TCP ||
	    tuple->nexthdr == IPPROTO_UDP) {
		struct {
			__be16 sport;
			__be16 dport;
		} l4hdr;
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return -EFAULT;
		tuple->sport = l4hdr.sport;
		tuple->dport = l4hdr.dport;
		return 0;
	}
	return -ENOTSUP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1166,
  "endLine": 1174,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_to_lb6_service",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool lb4_to_lb6_service (const struct lb4_service * svc __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NAT_46X64\n",
    "    return svc->flags2 & SVC_FLAG_NAT_46X64;\n",
    "\n",
    "#else\n",
    "    return false;\n",
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
static __always_inline bool
lb4_to_lb6_service(const struct lb4_service *svc __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	return svc->flags2 & SVC_FLAG_NAT_46X64;
#else
	return false;
#endif
}

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
  "startLine": 1176,
  "endLine": 1197,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_lookup_service",
  "developer_inline_comments": [
    {
      "start_line": 12,
      "end_line": 12,
      "text": "/* Packets for L7 LB are redirected even when there are no backends. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  LB4_SERVICES_MAP_V2"
  ],
  "input": [
    "struct lb4_key *key",
    " const bool scope_switch"
  ],
  "output": "static__always_inlinestructlb4_service",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb4_service *lb4_lookup_service (struct lb4_key *key, const bool scope_switch)\n",
    "{\n",
    "    struct lb4_service *svc;\n",
    "    key->scope = LB_LOOKUP_SCOPE_EXT;\n",
    "    key->backend_slot = 0;\n",
    "    svc = map_lookup_elem (& LB4_SERVICES_MAP_V2, key);\n",
    "    if (svc) {\n",
    "        if (!scope_switch || !lb4_svc_is_local_scope (svc))\n",
    "            return (svc->count || lb4_to_lb6_service (svc) || lb4_svc_is_l7loadbalancer (svc)) ? svc : NULL;\n",
    "        key->scope = LB_LOOKUP_SCOPE_INT;\n",
    "        svc = map_lookup_elem (& LB4_SERVICES_MAP_V2, key);\n",
    "        if (svc && (svc->count || lb4_svc_is_l7loadbalancer (svc)))\n",
    "            return svc;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb4_svc_is_l7loadbalancer",
    "lb4_svc_is_local_scope",
    "lb4_to_lb6_service"
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
struct lb4_service *lb4_lookup_service(struct lb4_key *key,
				       const bool scope_switch)
{
	struct lb4_service *svc;

	key->scope = LB_LOOKUP_SCOPE_EXT;
	key->backend_slot = 0;
	svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
	if (svc) {
		if (!scope_switch || !lb4_svc_is_local_scope(svc))
			/* Packets for L7 LB are redirected even when there are no backends. */
			return (svc->count || lb4_to_lb6_service(svc) ||
				lb4_svc_is_l7loadbalancer(svc)) ? svc : NULL;
		key->scope = LB_LOOKUP_SCOPE_INT;
		svc = map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
		if (svc && (svc->count || lb4_svc_is_l7loadbalancer(svc)))
			return svc;
	}

	return NULL;
}

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
  "startLine": 1199,
  "endLine": 1202,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb4_lookup_backend",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " LB4_BACKEND_MAP_V2"
  ],
  "input": [
    "__u32 backend_id"
  ],
  "output": "static__always_inlinestructlb4_backend",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb4_backend *__lb4_lookup_backend (__u32 backend_id)\n",
    "{\n",
    "    return map_lookup_elem (&LB4_BACKEND_MAP_V2, &backend_id);\n",
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
static __always_inline struct lb4_backend *__lb4_lookup_backend(__u32 backend_id)
{
	return map_lookup_elem(&LB4_BACKEND_MAP_V2, &backend_id);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1204,
  "endLine": 1214,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_lookup_backend",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinestructlb4_backend",
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
    "static __always_inline struct lb4_backend *lb4_lookup_backend (struct  __ctx_buff * ctx __maybe_unused, __u32 backend_id)\n",
    "{\n",
    "    struct lb4_backend *backend;\n",
    "    backend = __lb4_lookup_backend (backend_id);\n",
    "    if (!backend)\n",
    "        cilium_dbg_lb (ctx, DBG_LB4_LOOKUP_BACKEND_FAIL, backend_id, 0);\n",
    "    return backend;\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb4_lookup_backend",
    "cilium_dbg_lb"
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
static __always_inline struct lb4_backend *
lb4_lookup_backend(struct __ctx_buff *ctx __maybe_unused, __u32 backend_id)
{
	struct lb4_backend *backend;

	backend = __lb4_lookup_backend(backend_id);
	if (!backend)
		cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_FAIL, backend_id, 0);

	return backend;
}

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
  "startLine": 1216,
  "endLine": 1220,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb4_lookup_backend_slot",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " LB4_SERVICES_MAP_V2"
  ],
  "input": [
    "struct lb4_key *key"
  ],
  "output": "static__always_inlinestructlb4_service",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct lb4_service *__lb4_lookup_backend_slot (struct lb4_key *key)\n",
    "{\n",
    "    return map_lookup_elem (&LB4_SERVICES_MAP_V2, key);\n",
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
struct lb4_service *__lb4_lookup_backend_slot(struct lb4_key *key)
{
	return map_lookup_elem(&LB4_SERVICES_MAP_V2, key);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1222,
  "endLine": 1237,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_lookup_backend_slot",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct lb4_key *key",
    " __u16 slot"
  ],
  "output": "static__always_inlinestructlb4_service",
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
    "static __always_inline struct lb4_service *lb4_lookup_backend_slot (struct  __ctx_buff * ctx __maybe_unused, struct lb4_key *key, __u16 slot)\n",
    "{\n",
    "    struct lb4_service *svc;\n",
    "    key->backend_slot = slot;\n",
    "    cilium_dbg_lb (ctx, DBG_LB4_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);\n",
    "    svc = __lb4_lookup_backend_slot (key);\n",
    "    if (svc)\n",
    "        return svc;\n",
    "    cilium_dbg_lb (ctx, DBG_LB4_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_lb",
    "__lb4_lookup_backend_slot"
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
struct lb4_service *lb4_lookup_backend_slot(struct __ctx_buff *ctx __maybe_unused,
					    struct lb4_key *key, __u16 slot)
{
	struct lb4_service *svc;

	key->backend_slot = slot;
	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_SLOT, key->backend_slot, key->dport);
	svc = __lb4_lookup_backend_slot(key);
	if (svc)
		return svc;

	cilium_dbg_lb(ctx, DBG_LB4_LOOKUP_BACKEND_SLOT_V2_FAIL, key->backend_slot, key->dport);

	return NULL;
}

/* Backend slot 0 is always reserved for the service frontend. */
#if LB_SELECTION == LB_SELECTION_RANDOM
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1241,
  "endLine": 1251,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_select_backend_id",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* Backend slot 0 is always reserved for the service frontend. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct lb4_key *key",
    " const struct ipv4_ct_tuple * tuple __maybe_unused",
    " const struct lb4_service *svc"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb4_select_backend_id (struct  __ctx_buff *ctx, struct lb4_key *key, const struct ipv4_ct_tuple * tuple __maybe_unused, const struct lb4_service *svc)\n",
    "{\n",
    "    __u16 slot = (get_prandom_u32 () % svc->count) + 1;\n",
    "    struct lb4_service *be = lb4_lookup_backend_slot (ctx, key, slot);\n",
    "    return be ? be->backend_id : 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "hash_from_tuple_v4",
    "lb4_lookup_backend_slot",
    "map_array_get_32",
    "unlikely"
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
static __always_inline __u32
lb4_select_backend_id(struct __ctx_buff *ctx,
		      struct lb4_key *key,
		      const struct ipv4_ct_tuple *tuple __maybe_unused,
		      const struct lb4_service *svc)
{
	__u16 slot = (get_prandom_u32() % svc->count) + 1;
	struct lb4_service *be = lb4_lookup_backend_slot(ctx, key, slot);

	return be ? be->backend_id : 0;
}
#elif LB_SELECTION == LB_SELECTION_MAGLEV
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
  "startLine": 1253,
  "endLine": 1273,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_select_backend_id",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  LB4_MAGLEV_MAP_OUTER",
    " maglev_lut"
  ],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " struct lb4_key * key __maybe_unused",
    " const struct ipv4_ct_tuple *tuple",
    " const struct lb4_service *svc"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u32 lb4_select_backend_id (struct  __ctx_buff * ctx __maybe_unused, struct lb4_key * key __maybe_unused, const struct ipv4_ct_tuple *tuple, const struct lb4_service *svc)\n",
    "{\n",
    "    __u32 zero = 0, index = svc->rev_nat_index;\n",
    "    __u32 *backend_ids;\n",
    "    void *maglev_lut;\n",
    "    maglev_lut = map_lookup_elem (& LB4_MAGLEV_MAP_OUTER, & index);\n",
    "    if (unlikely (!maglev_lut))\n",
    "        return 0;\n",
    "    backend_ids = map_lookup_elem (maglev_lut, & zero);\n",
    "    if (unlikely (!backend_ids))\n",
    "        return 0;\n",
    "    index = hash_from_tuple_v4 (tuple) % LB_MAGLEV_LUT_SIZE;\n",
    "    return map_array_get_32 (backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);\n",
    "}\n"
  ],
  "called_function_list": [
    "hash_from_tuple_v4",
    "lb4_lookup_backend_slot",
    "map_array_get_32",
    "unlikely"
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
static __always_inline __u32
lb4_select_backend_id(struct __ctx_buff *ctx __maybe_unused,
		      struct lb4_key *key __maybe_unused,
		      const struct ipv4_ct_tuple *tuple,
		      const struct lb4_service *svc)
{
	__u32 zero = 0, index = svc->rev_nat_index;
	__u32 *backend_ids;
	void *maglev_lut;

	maglev_lut = map_lookup_elem(&LB4_MAGLEV_MAP_OUTER, &index);
	if (unlikely(!maglev_lut))
		return 0;

	backend_ids = map_lookup_elem(maglev_lut, &zero);
	if (unlikely(!backend_ids))
		return 0;

	index = hash_from_tuple_v4(tuple) % LB_MAGLEV_LUT_SIZE;
        return map_array_get_32(backend_ids, index, (LB_MAGLEV_LUT_SIZE - 1) << 2);
}
#else
# error "Invalid load balancer backend selection algorithm!"
#endif /* LB_SELECTION */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "cilium",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with l3_csum_replace() and l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1278,
  "endLine": 1332,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_xlate",
  "developer_inline_comments": [
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* LB_SELECTION */"
    },
    {
      "start_line": 34,
      "end_line": 34,
      "text": "/* DISABLE_LOOPBACK_LB */"
    },
    {
      "start_line": 50,
      "end_line": 50,
      "text": "/* Port offsets for UDP and TCP are the same */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __be32 *new_daddr",
    " __be32 * new_saddr __maybe_unused",
    " __be32 * old_saddr __maybe_unused",
    " __u8 nexthdr __maybe_unused",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct lb4_key *key",
    " const struct lb4_backend * backend __maybe_unused",
    " bool has_l4_header",
    " const bool skip_l3_xlate"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK",
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int lb4_xlate (struct  __ctx_buff *ctx, __be32 *new_daddr, __be32 * new_saddr __maybe_unused, __be32 * old_saddr __maybe_unused, __u8 nexthdr __maybe_unused, int l3_off, int l4_off, struct csum_offset *csum_off, struct lb4_key *key, const struct lb4_backend * backend __maybe_unused, bool has_l4_header, const bool skip_l3_xlate)\n",
    "{\n",
    "    __be32 sum;\n",
    "    int ret;\n",
    "    if (skip_l3_xlate)\n",
    "        goto l4_xlate;\n",
    "    ret = ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, daddr), new_daddr, 4, 0);\n",
    "    if (ret < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    sum = csum_diff (& key -> address, 4, new_daddr, 4, 0);\n",
    "\n",
    "#ifndef DISABLE_LOOPBACK_LB\n",
    "    if (new_saddr && *new_saddr) {\n",
    "        cilium_dbg_lb (ctx, DBG_LB4_LOOPBACK_SNAT, *old_saddr, *new_saddr);\n",
    "        ret = ctx_store_bytes (ctx, l3_off + offsetof (struct iphdr, saddr), new_saddr, 4, 0);\n",
    "        if (ret < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        sum = csum_diff (old_saddr, 4, new_saddr, 4, sum);\n",
    "    }\n",
    "\n",
    "#endif /* DISABLE_LOOPBACK_LB */\n",
    "    if (l3_csum_replace (ctx, l3_off + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    if (csum_off->offset) {\n",
    "        if (csum_l4_replace (ctx, l4_off, csum_off, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "            return DROP_CSUM_L4;\n",
    "    }\n",
    "l4_xlate :\n",
    "    if (likely (backend->port) && key->dport != backend->port && (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) && has_l4_header) {\n",
    "        __be16 tmp = backend->port;\n",
    "        ret = l4_modify_port (ctx, l4_off, TCP_DPORT_OFF, csum_off, tmp, key -> dport);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "ctx_store_bytes",
    "IS_ERR",
    "offsetof",
    "csum_l4_replace",
    "cilium_dbg_lb",
    "likely"
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
static __always_inline int
lb4_xlate(struct __ctx_buff *ctx, __be32 *new_daddr, __be32 *new_saddr __maybe_unused,
	  __be32 *old_saddr __maybe_unused, __u8 nexthdr __maybe_unused, int l3_off,
	  int l4_off, struct csum_offset *csum_off, struct lb4_key *key,
	  const struct lb4_backend *backend __maybe_unused, bool has_l4_header,
	  const bool skip_l3_xlate)
{
	__be32 sum;
	int ret;

	if (skip_l3_xlate)
		goto l4_xlate;

	ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, daddr),
			      new_daddr, 4, 0);
	if (ret < 0)
		return DROP_WRITE_ERROR;

	sum = csum_diff(&key->address, 4, new_daddr, 4, 0);
#ifndef DISABLE_LOOPBACK_LB
	if (new_saddr && *new_saddr) {
		cilium_dbg_lb(ctx, DBG_LB4_LOOPBACK_SNAT, *old_saddr, *new_saddr);

		ret = ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, saddr),
				      new_saddr, 4, 0);
		if (ret < 0)
			return DROP_WRITE_ERROR;

		sum = csum_diff(old_saddr, 4, new_saddr, 4, sum);
	}
#endif /* DISABLE_LOOPBACK_LB */
	if (l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (csum_off->offset) {
		if (csum_l4_replace(ctx, l4_off, csum_off, 0, sum,
				    BPF_F_PSEUDO_HDR) < 0)
			return DROP_CSUM_L4;
	}

l4_xlate:
	if (likely(backend->port) && key->dport != backend->port &&
	    (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) &&
	    has_l4_header) {
		__be16 tmp = backend->port;

		/* Port offsets for UDP and TCP are the same */
		ret = l4_modify_port(ctx, l4_off, TCP_DPORT_OFF, csum_off,
				     tmp, key->dport);
		if (IS_ERR(ret))
			return ret;
	}

	return CTX_ACT_OK;
}

#ifdef ENABLE_SESSION_AFFINITY
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
  "startLine": 1335,
  "endLine": 1375,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb4_affinity_backend_id",
  "developer_inline_comments": [
    {
      "start_line": 21,
      "end_line": 25,
      "text": "/* We have seconds granularity for timing values here.\n\t\t * To ensure that session affinity timeout works properly we don't include\n\t\t * the upper bound from the time range.\n\t\t * Session is sticky for range [current, last_used + affinity_timeout)\n\t\t */"
    }
  ],
  "updateMaps": [
    " LB4_AFFINITY_MAP"
  ],
  "readMaps": [
    " LB_AFFINITY_MATCH_MAP",
    "  LB4_AFFINITY_MAP"
  ],
  "input": [
    "const struct lb4_service *svc",
    " bool netns_cookie",
    " const union lb4_affinity_client_id *id"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem",
    "map_delete_elem"
  ],
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
    "sched_cls",
    "sk_skb",
    "socket_filter",
    "cgroup_skb",
    "sk_msg",
    "lwt_in",
    "raw_tracepoint_writable"
  ],
  "source": [
    "static __always_inline __u32 __lb4_affinity_backend_id (const struct lb4_service *svc, bool netns_cookie, const union lb4_affinity_client_id *id)\n",
    "{\n",
    "    struct lb4_affinity_key key = {\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .netns_cookie = netns_cookie,\n",
    "        .client_id = *id,}\n",
    "    ;\n",
    "    struct lb_affinity_val *val;\n",
    "    val = map_lookup_elem (& LB4_AFFINITY_MAP, & key);\n",
    "    if (val != NULL) {\n",
    "        __u32 now = bpf_mono_now ();\n",
    "        struct lb_affinity_match match = {\n",
    "            .rev_nat_id = svc->rev_nat_index,\n",
    "            .backend_id = val->backend_id,}\n",
    "        ;\n",
    "        if (READ_ONCE (val->last_used) + bpf_sec_to_mono (svc->affinity_timeout) <= now) {\n",
    "            map_delete_elem (&LB4_AFFINITY_MAP, &key);\n",
    "            return 0;\n",
    "        }\n",
    "        if (!map_lookup_elem (&LB_AFFINITY_MATCH_MAP, &match)) {\n",
    "            map_delete_elem (&LB4_AFFINITY_MAP, &key);\n",
    "            return 0;\n",
    "        }\n",
    "        WRITE_ONCE (val->last_used, now);\n",
    "        return val->backend_id;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_mono_now",
    "READ_ONCE",
    "bpf_sec_to_mono",
    "WRITE_ONCE"
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
static __always_inline __u32
__lb4_affinity_backend_id(const struct lb4_service *svc, bool netns_cookie,
			  const union lb4_affinity_client_id *id)
{
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};
	struct lb_affinity_val *val;

	val = map_lookup_elem(&LB4_AFFINITY_MAP, &key);
	if (val != NULL) {
		__u32 now = bpf_mono_now();
		struct lb_affinity_match match = {
			.rev_nat_id	= svc->rev_nat_index,
			.backend_id	= val->backend_id,
		};

		/* We have seconds granularity for timing values here.
		 * To ensure that session affinity timeout works properly we don't include
		 * the upper bound from the time range.
		 * Session is sticky for range [current, last_used + affinity_timeout)
		 */
		if (READ_ONCE(val->last_used) +
		    bpf_sec_to_mono(svc->affinity_timeout) <= now) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
			map_delete_elem(&LB4_AFFINITY_MAP, &key);
			return 0;
		}

		WRITE_ONCE(val->last_used, now);
		return val->backend_id;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1377,
  "endLine": 1382,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_affinity_backend_id_by_addr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc",
    " union lb4_affinity_client_id *id"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb4_affinity_backend_id_by_addr (const struct lb4_service *svc, union lb4_affinity_client_id *id)\n",
    "{\n",
    "    return __lb4_affinity_backend_id (svc, false, id);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb4_affinity_backend_id"
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
static __always_inline __u32
lb4_affinity_backend_id_by_addr(const struct lb4_service *svc,
				union lb4_affinity_client_id *id)
{
	return __lb4_affinity_backend_id(svc, false, id);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1384,
  "endLine": 1401,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "__lb4_update_affinity",
  "developer_inline_comments": [],
  "updateMaps": [
    " LB4_AFFINITY_MAP"
  ],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc",
    " bool netns_cookie",
    " const union lb4_affinity_client_id *id",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "map_update_elem"
  ],
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
    "static __always_inline void __lb4_update_affinity (const struct lb4_service *svc, bool netns_cookie, const union lb4_affinity_client_id *id, __u32 backend_id)\n",
    "{\n",
    "    __u32 now = bpf_mono_now ();\n",
    "    struct lb4_affinity_key key = {\n",
    "        .rev_nat_id = svc->rev_nat_index,\n",
    "        .netns_cookie = netns_cookie,\n",
    "        .client_id = *id,}\n",
    "    ;\n",
    "    struct lb_affinity_val val = {\n",
    "        .backend_id = backend_id,\n",
    "        .last_used = now,}\n",
    "    ;\n",
    "    map_update_elem (&LB4_AFFINITY_MAP, &key, &val, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_mono_now"
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
static __always_inline void
__lb4_update_affinity(const struct lb4_service *svc, bool netns_cookie,
		      const union lb4_affinity_client_id *id,
		      __u32 backend_id)
{
	__u32 now = bpf_mono_now();
	struct lb4_affinity_key key = {
		.rev_nat_id	= svc->rev_nat_index,
		.netns_cookie	= netns_cookie,
		.client_id	= *id,
	};
	struct lb_affinity_val val = {
		.backend_id	= backend_id,
		.last_used	= now,
	};

	map_update_elem(&LB4_AFFINITY_MAP, &key, &val, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1403,
  "endLine": 1408,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_update_affinity_by_addr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service *svc",
    " union lb4_affinity_client_id *id",
    " __u32 backend_id"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb4_update_affinity_by_addr (const struct lb4_service *svc, union lb4_affinity_client_id *id, __u32 backend_id)\n",
    "{\n",
    "    __lb4_update_affinity (svc, false, id, backend_id);\n",
    "}\n"
  ],
  "called_function_list": [
    "__lb4_update_affinity"
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
static __always_inline void
lb4_update_affinity_by_addr(const struct lb4_service *svc,
			    union lb4_affinity_client_id *id, __u32 backend_id)
{
	__lb4_update_affinity(svc, false, id, backend_id);
}
#endif /* ENABLE_SESSION_AFFINITY */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1411,
  "endLine": 1420,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_affinity_backend_id_by_netns",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused",
    " union lb4_affinity_client_id * id __maybe_unused"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 lb4_affinity_backend_id_by_netns (const struct lb4_service * svc __maybe_unused, union lb4_affinity_client_id * id __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(ENABLE_SESSION_AFFINITY)\n",
    "    return __lb4_affinity_backend_id (svc, true, id);\n",
    "\n",
    "#else\n",
    "    return 0;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "__lb4_affinity_backend_id"
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
static __always_inline __u32
lb4_affinity_backend_id_by_netns(const struct lb4_service *svc __maybe_unused,
				 union lb4_affinity_client_id *id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
	return __lb4_affinity_backend_id(svc, true, id);
#else
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1422,
  "endLine": 1430,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_update_affinity_by_netns",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct lb4_service * svc __maybe_unused",
    " union lb4_affinity_client_id * id __maybe_unused",
    " __u32 backend_id __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb4_update_affinity_by_netns (const struct lb4_service * svc __maybe_unused, union lb4_affinity_client_id * id __maybe_unused, __u32 backend_id __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(ENABLE_SESSION_AFFINITY)\n",
    "    __lb4_update_affinity (svc, true, id, backend_id);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "defined",
    "__lb4_update_affinity"
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
static __always_inline void
lb4_update_affinity_by_netns(const struct lb4_service *svc __maybe_unused,
			     union lb4_affinity_client_id *id __maybe_unused,
			     __u32 backend_id __maybe_unused)
{
#if defined(ENABLE_SESSION_AFFINITY)
	__lb4_update_affinity(svc, true, id, backend_id);
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1432,
  "endLine": 1447,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_to_lb6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " const struct iphdr * ip4 __maybe_unused",
    " int l3_off __maybe_unused"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int lb4_to_lb6 (struct  __ctx_buff * ctx __maybe_unused, const struct iphdr * ip4 __maybe_unused, int l3_off __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_NAT_46X64\n",
    "    union v6addr src6, dst6;\n",
    "    build_v4_in_v6 (&src6, ip4->saddr);\n",
    "    build_v4_in_v6 (&dst6, ip4->daddr);\n",
    "    return ipv4_to_ipv6 (ctx, l3_off, &src6, &dst6);\n",
    "\n",
    "#else\n",
    "    return DROP_NAT_46X64_DISABLED;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "build_v4_in_v6",
    "ipv4_to_ipv6"
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
static __always_inline int
lb4_to_lb6(struct __ctx_buff *ctx __maybe_unused,
	   const struct iphdr *ip4 __maybe_unused,
	   int l3_off __maybe_unused)
{
#ifdef ENABLE_NAT_46X64
	union v6addr src6, dst6;

	build_v4_in_v6(&src6, ip4->saddr);
	build_v4_in_v6(&dst6, ip4->daddr);

	return ipv4_to_ipv6(ctx, l3_off, &src6, &dst6);
#else
	return DROP_NAT_46X64_DISABLED;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "xdp",
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1449,
  "endLine": 1604,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_local",
  "developer_inline_comments": [
    {
      "start_line": 11,
      "end_line": 11,
      "text": "/* Deliberately ignored; regular CT will determine monitoring. */"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "/* No CT entry has been found, so select a svc endpoint */"
    },
    {
      "start_line": 47,
      "end_line": 49,
      "text": "/* Fail closed, if the conntrack entry create fails drop\n\t\t * service lookup.\n\t\t */"
    },
    {
      "start_line": 57,
      "end_line": 62,
      "text": "/* For backward-compatibility we need to update reverse NAT\n\t\t * index in the CT_SERVICE entry for old connections, as later\n\t\t * in the code we check whether the right backend is used.\n\t\t * Having it set to 0 would trigger a new backend selection\n\t\t * which would in many cases would pick a different backend.\n\t\t */"
    },
    {
      "start_line": 72,
      "end_line": 78,
      "text": "/* If the CT_SERVICE entry is from a non-related connection (e.g.\n\t * endpoint has been removed, but its CT entries were not (it is\n\t * totally possible due to the bug in DumpReliablyWithCallback)),\n\t * then a wrong (=from unrelated service) backend can be selected.\n\t * To avoid this, check that reverse NAT indices match. If not,\n\t * select a new backend.\n\t */"
    },
    {
      "start_line": 96,
      "end_line": 99,
      "text": "/* If the lookup fails it means the user deleted the backend out from\n\t * underneath us. To resolve this fall back to hash. If this is a TCP\n\t * session we are likely to get a TCP RST.\n\t */"
    },
    {
      "start_line": 102,
      "end_line": 104,
      "text": "/* Drain existing connections, but redirect new ones to only\n\t\t * active backends.\n\t\t */"
    },
    {
      "start_line": 119,
      "end_line": 121,
      "text": "/* Restore flags so that SERVICE flag is only used in used when the\n\t * service lookup happens and future lookups use EGRESS or INGRESS.\n\t */"
    },
    {
      "start_line": 131,
      "end_line": 137,
      "text": "/* Special loopback case: The origin endpoint has transmitted to a\n\t * service which is being translated back to the source. This would\n\t * result in a packet with identical source and destination address.\n\t * Linux considers such packets as martian source and will drop unless\n\t * received on a loopback device. Perform NAT on the source address\n\t * to make it appear from an outside address.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *map",
    " struct  __ctx_buff *ctx",
    " int l3_off",
    " int l4_off",
    " struct csum_offset *csum_off",
    " struct lb4_key *key",
    " struct ipv4_ct_tuple *tuple",
    " const struct lb4_service *svc",
    " struct ct_state *state",
    " __be32 saddr",
    " bool has_l4_header",
    " const bool skip_l3_xlate"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline int lb4_local (const void *map, struct  __ctx_buff *ctx, int l3_off, int l4_off, struct csum_offset *csum_off, struct lb4_key *key, struct ipv4_ct_tuple *tuple, const struct lb4_service *svc, struct ct_state *state, __be32 saddr, bool has_l4_header, const bool skip_l3_xlate)\n",
    "{\n",
    "    __u32 monitor;\n",
    "    __be32 new_saddr = 0, new_daddr;\n",
    "    __u8 flags = tuple->flags;\n",
    "    struct lb4_backend *backend;\n",
    "    __u32 backend_id = 0;\n",
    "    int ret;\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "    union lb4_affinity_client_id client_id = {\n",
    "        .client_ip = saddr,}\n",
    "    ;\n",
    "\n",
    "#endif\n",
    "    ret = ct_lookup4 (map, tuple, ctx, l4_off, CT_SERVICE, state, & monitor);\n",
    "    switch (ret) {\n",
    "    case CT_NEW :\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "        if (lb4_svc_is_affinity (svc)) {\n",
    "            backend_id = lb4_affinity_backend_id_by_addr (svc, & client_id);\n",
    "            if (backend_id != 0) {\n",
    "                backend = lb4_lookup_backend (ctx, backend_id);\n",
    "                if (backend == NULL)\n",
    "                    backend_id = 0;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        if (backend_id == 0) {\n",
    "            backend_id = lb4_select_backend_id (ctx, key, tuple, svc);\n",
    "            backend = lb4_lookup_backend (ctx, backend_id);\n",
    "            if (backend == NULL)\n",
    "                goto drop_no_service;\n",
    "        }\n",
    "        state->backend_id = backend_id;\n",
    "        state->rev_nat_index = svc->rev_nat_index;\n",
    "        ret = ct_create4 (map, NULL, tuple, ctx, CT_SERVICE, state, false, false);\n",
    "        if (IS_ERR (ret))\n",
    "            goto drop_no_service;\n",
    "        goto update_state;\n",
    "    case CT_REOPENED :\n",
    "    case CT_ESTABLISHED :\n",
    "    case CT_RELATED :\n",
    "    case CT_REPLY :\n",
    "        if (unlikely (state->rev_nat_index == 0)) {\n",
    "            state->rev_nat_index = svc->rev_nat_index;\n",
    "            ct_update4_rev_nat_index (map, tuple, state);\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        goto drop_no_service;\n",
    "    }\n",
    "    if (state->rev_nat_index != svc->rev_nat_index) {\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "        if (lb4_svc_is_affinity (svc))\n",
    "            backend_id = lb4_affinity_backend_id_by_addr (svc, &client_id);\n",
    "\n",
    "#endif\n",
    "        if (!backend_id) {\n",
    "            backend_id = lb4_select_backend_id (ctx, key, tuple, svc);\n",
    "            if (!backend_id)\n",
    "                goto drop_no_service;\n",
    "        }\n",
    "        state->backend_id = backend_id;\n",
    "        ct_update4_backend_id (map, tuple, state);\n",
    "        state->rev_nat_index = svc->rev_nat_index;\n",
    "        ct_update4_rev_nat_index (map, tuple, state);\n",
    "    }\n",
    "    backend = lb4_lookup_backend (ctx, state -> backend_id);\n",
    "    if (unlikely (!backend || backend->flags != BE_STATE_ACTIVE)) {\n",
    "        if (backend && !state->syn)\n",
    "            goto update_state;\n",
    "        key->backend_slot = 0;\n",
    "        svc = lb4_lookup_service (key, false);\n",
    "        if (!svc)\n",
    "            goto drop_no_service;\n",
    "        backend_id = lb4_select_backend_id (ctx, key, tuple, svc);\n",
    "        backend = lb4_lookup_backend (ctx, backend_id);\n",
    "        if (!backend)\n",
    "            goto drop_no_service;\n",
    "        state->backend_id = backend_id;\n",
    "        ct_update4_backend_id (map, tuple, state);\n",
    "    }\n",
    "update_state :\n",
    "    tuple->flags = flags;\n",
    "    state->rev_nat_index = svc->rev_nat_index;\n",
    "    state->addr = new_daddr = backend->address;\n",
    "\n",
    "#ifdef ENABLE_SESSION_AFFINITY\n",
    "    if (lb4_svc_is_affinity (svc))\n",
    "        lb4_update_affinity_by_addr (svc, &client_id, state->backend_id);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifndef DISABLE_LOOPBACK_LB\n",
    "    if (saddr == backend->address) {\n",
    "        new_saddr = IPV4_LOOPBACK;\n",
    "        state->loopback = 1;\n",
    "        state->addr = new_saddr;\n",
    "        state->svc_addr = saddr;\n",
    "    }\n",
    "    if (!state->loopback)\n",
    "\n",
    "#endif\n",
    "        tuple->daddr = backend->address;\n",
    "    return lb_skip_l4_dnat () ? CTX_ACT_OK : lb4_xlate (ctx, &new_daddr, &new_saddr, &saddr, tuple->nexthdr, l3_off, l4_off, csum_off, key, backend, has_l4_header, skip_l3_xlate);\n",
    "drop_no_service :\n",
    "    tuple->flags = flags;\n",
    "    return DROP_NO_SERVICE;\n",
    "}\n"
  ],
  "called_function_list": [
    "lb4_select_backend_id",
    "lb4_svc_is_affinity",
    "ct_lookup4",
    "lb4_affinity_backend_id_by_addr",
    "lb4_update_affinity_by_addr",
    "IS_ERR",
    "ct_create4",
    "lb4_lookup_service",
    "unlikely",
    "lb4_lookup_backend",
    "ct_update4_rev_nat_index",
    "ct_update4_backend_id",
    "lb_skip_l4_dnat",
    "lb4_xlate"
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
static __always_inline int lb4_local(const void *map, struct __ctx_buff *ctx,
				     int l3_off, int l4_off,
				     struct csum_offset *csum_off,
				     struct lb4_key *key,
				     struct ipv4_ct_tuple *tuple,
				     const struct lb4_service *svc,
				     struct ct_state *state, __be32 saddr,
				     bool has_l4_header,
				     const bool skip_l3_xlate)
{
	__u32 monitor; /* Deliberately ignored; regular CT will determine monitoring. */
	__be32 new_saddr = 0, new_daddr;
	__u8 flags = tuple->flags;
	struct lb4_backend *backend;
	__u32 backend_id = 0;
	int ret;
#ifdef ENABLE_SESSION_AFFINITY
	union lb4_affinity_client_id client_id = {
		.client_ip = saddr,
	};
#endif
	ret = ct_lookup4(map, tuple, ctx, l4_off, CT_SERVICE, state, &monitor);
	switch (ret) {
	case CT_NEW:
#ifdef ENABLE_SESSION_AFFINITY
		if (lb4_svc_is_affinity(svc)) {
			backend_id = lb4_affinity_backend_id_by_addr(svc, &client_id);
			if (backend_id != 0) {
				backend = lb4_lookup_backend(ctx, backend_id);
				if (backend == NULL)
					backend_id = 0;
			}
		}
#endif
		if (backend_id == 0) {
			/* No CT entry has been found, so select a svc endpoint */
			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			backend = lb4_lookup_backend(ctx, backend_id);
			if (backend == NULL)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		state->rev_nat_index = svc->rev_nat_index;

		ret = ct_create4(map, NULL, tuple, ctx, CT_SERVICE, state, false, false);
		/* Fail closed, if the conntrack entry create fails drop
		 * service lookup.
		 */
		if (IS_ERR(ret))
			goto drop_no_service;
		goto update_state;
	case CT_REOPENED:
	case CT_ESTABLISHED:
	case CT_RELATED:
	case CT_REPLY:
		/* For backward-compatibility we need to update reverse NAT
		 * index in the CT_SERVICE entry for old connections, as later
		 * in the code we check whether the right backend is used.
		 * Having it set to 0 would trigger a new backend selection
		 * which would in many cases would pick a different backend.
		 */
		if (unlikely(state->rev_nat_index == 0)) {
			state->rev_nat_index = svc->rev_nat_index;
			ct_update4_rev_nat_index(map, tuple, state);
		}
		break;
	default:
		goto drop_no_service;
	}

	/* If the CT_SERVICE entry is from a non-related connection (e.g.
	 * endpoint has been removed, but its CT entries were not (it is
	 * totally possible due to the bug in DumpReliablyWithCallback)),
	 * then a wrong (=from unrelated service) backend can be selected.
	 * To avoid this, check that reverse NAT indices match. If not,
	 * select a new backend.
	 */
	if (state->rev_nat_index != svc->rev_nat_index) {
#ifdef ENABLE_SESSION_AFFINITY
		if (lb4_svc_is_affinity(svc))
			backend_id = lb4_affinity_backend_id_by_addr(svc,
								     &client_id);
#endif
		if (!backend_id) {
			backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
			if (!backend_id)
				goto drop_no_service;
		}

		state->backend_id = backend_id;
		ct_update4_backend_id(map, tuple, state);
		state->rev_nat_index = svc->rev_nat_index;
		ct_update4_rev_nat_index(map, tuple, state);
	}
	/* If the lookup fails it means the user deleted the backend out from
	 * underneath us. To resolve this fall back to hash. If this is a TCP
	 * session we are likely to get a TCP RST.
	 */
	backend = lb4_lookup_backend(ctx, state->backend_id);
	if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
		/* Drain existing connections, but redirect new ones to only
		 * active backends.
		 */
		if (backend && !state->syn)
			goto update_state;
		key->backend_slot = 0;
		svc = lb4_lookup_service(key, false);
		if (!svc)
			goto drop_no_service;
		backend_id = lb4_select_backend_id(ctx, key, tuple, svc);
		backend = lb4_lookup_backend(ctx, backend_id);
		if (!backend)
			goto drop_no_service;
		state->backend_id = backend_id;
		ct_update4_backend_id(map, tuple, state);
	}
update_state:
	/* Restore flags so that SERVICE flag is only used in used when the
	 * service lookup happens and future lookups use EGRESS or INGRESS.
	 */
	tuple->flags = flags;
	state->rev_nat_index = svc->rev_nat_index;
	state->addr = new_daddr = backend->address;
#ifdef ENABLE_SESSION_AFFINITY
	if (lb4_svc_is_affinity(svc))
		lb4_update_affinity_by_addr(svc, &client_id,
					    state->backend_id);
#endif
#ifndef DISABLE_LOOPBACK_LB
	/* Special loopback case: The origin endpoint has transmitted to a
	 * service which is being translated back to the source. This would
	 * result in a packet with identical source and destination address.
	 * Linux considers such packets as martian source and will drop unless
	 * received on a loopback device. Perform NAT on the source address
	 * to make it appear from an outside address.
	 */
	if (saddr == backend->address) {
		new_saddr = IPV4_LOOPBACK;
		state->loopback = 1;
		state->addr = new_saddr;
		state->svc_addr = saddr;
	}

	if (!state->loopback)
#endif
		tuple->daddr = backend->address;

	return lb_skip_l4_dnat() ? CTX_ACT_OK :
	       lb4_xlate(ctx, &new_daddr, &new_saddr, &saddr,
			 tuple->nexthdr, l3_off, l4_off, csum_off, key,
			 backend, has_l4_header, skip_l3_xlate);
drop_no_service:
	tuple->flags = flags;
	return DROP_NO_SERVICE;
}

/* lb4_ctx_store_state() stores per packet load balancing state to be picked
 * up on the continuation tail call.
 * Note that the IP headers are already xlated and the tuple is re-initialized
 * from the xlated headers before restoring state.
 * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We
 * lose the updated tuple daddr in that case.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1613,
  "endLine": 1621,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_ctx_store_state",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 7,
      "text": "/* lb4_ctx_store_state() stores per packet load balancing state to be picked\n * up on the continuation tail call.\n * Note that the IP headers are already xlated and the tuple is re-initialized\n * from the xlated headers before restoring state.\n * NOTE: if lb_skip_l4_dnat() this is not the case as xlate is skipped. We\n * lose the updated tuple daddr in that case.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ct_state *state",
    " __u16 proxy_port"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb4_ctx_store_state (struct  __ctx_buff *ctx, const struct ct_state *state, __u16 proxy_port)\n",
    "{\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, (__u32) proxy_port << 16);\n",
    "    ctx_store_meta (ctx, CB_BACKEND_ID, state->backend_id);\n",
    "    ctx_store_meta (ctx, CB_CT_STATE, (__u32) state->rev_nat_index << 16 | state->loopback);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta"
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
static __always_inline void lb4_ctx_store_state(struct __ctx_buff *ctx,
						const struct ct_state *state,
					       __u16 proxy_port)
{
	ctx_store_meta(ctx, CB_PROXY_MAGIC, (__u32)proxy_port << 16);
	ctx_store_meta(ctx, CB_BACKEND_ID, state->backend_id);
	ctx_store_meta(ctx, CB_CT_STATE, (__u32)state->rev_nat_index << 16 |
		       state->loopback);
}

/* lb4_ctx_restore_state() restores per packet load balancing state from the
 * previous tail call.
 * tuple->flags does not need to be restored, as it will be reinitialized from
 * the packet.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1628,
  "endLine": 1651,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/lb.h",
  "funcName": "lb4_ctx_restore_state",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "/* lb4_ctx_restore_state() restores per packet load balancing state from the\n * previous tail call.\n * tuple->flags does not need to be restored, as it will be reinitialized from\n * the packet.\n */"
    },
    {
      "start_line": 15,
      "end_line": 15,
      "text": "/* backend address after xlate */"
    },
    {
      "start_line": 20,
      "end_line": 20,
      "text": "/* Clear to not leak state to later stages of the datapath. */"
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": "/* must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ct_state *state",
    " __u32 daddr __maybe_unused",
    " __u16 *proxy_port"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void lb4_ctx_restore_state (struct  __ctx_buff *ctx, struct ct_state *state, __u32 daddr __maybe_unused, __u16 *proxy_port)\n",
    "{\n",
    "    __u32 meta = ctx_load_meta (ctx, CB_CT_STATE);\n",
    "\n",
    "#ifndef DISABLE_LOOPBACK_LB\n",
    "    if (meta & 1) {\n",
    "        state->loopback = 1;\n",
    "        state->addr = IPV4_LOOPBACK;\n",
    "        state->svc_addr = daddr;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    state->rev_nat_index = meta >> 16;\n",
    "    ctx_store_meta (ctx, CB_CT_STATE, 0);\n",
    "    state->backend_id = ctx_load_meta (ctx, CB_BACKEND_ID);\n",
    "    ctx_store_meta (ctx, CB_BACKEND_ID, 0);\n",
    "    *proxy_port = ctx_load_meta (ctx, CB_PROXY_MAGIC) >> 16;\n",
    "    ctx_store_meta (ctx, CB_PROXY_MAGIC, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_store_meta",
    "ctx_load_meta"
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
static __always_inline void
lb4_ctx_restore_state(struct __ctx_buff *ctx, struct ct_state *state,
		      __u32 daddr __maybe_unused, __u16 *proxy_port)
{
	__u32 meta = ctx_load_meta(ctx, CB_CT_STATE);
#ifndef DISABLE_LOOPBACK_LB
	if (meta & 1) {
		state->loopback = 1;
		state->addr = IPV4_LOOPBACK;
		state->svc_addr = daddr; /* backend address after xlate */
	}
#endif
	state->rev_nat_index = meta >> 16;

	/* Clear to not leak state to later stages of the datapath. */
	ctx_store_meta(ctx, CB_CT_STATE, 0);

	state->backend_id = ctx_load_meta(ctx, CB_BACKEND_ID);
	/* must clear to avoid policy bypass as CB_BACKEND_ID aliases CB_POLICY. */
	ctx_store_meta(ctx, CB_BACKEND_ID, 0);

	*proxy_port = ctx_load_meta(ctx, CB_PROXY_MAGIC) >> 16;
	ctx_store_meta(ctx, CB_PROXY_MAGIC, 0);
}
#endif /* ENABLE_IPV4 */
#endif /* __LB_H_ */
