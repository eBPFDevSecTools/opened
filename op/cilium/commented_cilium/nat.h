/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Simple NAT engine in BPF. */
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "common.h"
#include "drop.h"
#include "signal.h"
#include "conntrack.h"
#include "conntrack_map.h"
#include "icmp6.h"
#include "nat_46x64.h"

enum  nat_dir {
	NAT_DIR_EGRESS  = TUPLE_F_OUT,
	NAT_DIR_INGRESS = TUPLE_F_IN,
} __packed;

struct nat_entry {
	__u64 created;
	__u64 host_local;	/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

#define NAT_CONTINUE_XLATE	0

#ifdef HAVE_LRU_HASH_MAP_TYPE
# define NAT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
# define NAT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifdef HAVE_LARGE_INSN_LIMIT
# define SNAT_COLLISION_RETRIES		128
# define SNAT_SIGNAL_THRES		64
#else
# define SNAT_COLLISION_RETRIES		32
# define SNAT_SIGNAL_THRES		16
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 51,
  "endLine": 55,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "__snat_clamp_port_range",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 start",
    " __u16 end",
    " __u16 val"
  ],
  "output": "static__always_inline__be16",
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
    "static __always_inline __be16 __snat_clamp_port_range (__u16 start, __u16 end, __u16 val)\n",
    "{\n",
    "    return (val % (__u16) (end - start)) + start;\n",
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
static __always_inline __be16 __snat_clamp_port_range(__u16 start, __u16 end,
						      __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 62,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "__snat_try_keep_port",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 start",
    " __u16 end",
    " __u16 val"
  ],
  "output": "static__always_inline__maybe_unused__be16",
  "helper": [
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "cgroup_sock_addr",
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
    "perf_event",
    "cgroup_sock",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline __maybe_unused __be16 __snat_try_keep_port (__u16 start, __u16 end, __u16 val)\n",
    "{\n",
    "    return val >= start && val <= end ? val : __snat_clamp_port_range (start, end, (__u16) get_prandom_u32 ());\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_clamp_port_range"
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
static __always_inline __maybe_unused __be16
__snat_try_keep_port(__u16 start, __u16 end, __u16 val)
{
	return val >= start && val <= end ? val :
	       __snat_clamp_port_range(start, end, (__u16)get_prandom_u32());
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
  "startLine": 64,
  "endLine": 68,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "__snat_lookup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "const void *map",
    " const void *tuple"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "map_lookup_elem"
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
    "static __always_inline __maybe_unused void *__snat_lookup (const void *map, const void *tuple)\n",
    "{\n",
    "    return map_lookup_elem (map, tuple);\n",
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
static __always_inline __maybe_unused void *
__snat_lookup(const void *map, const void *tuple)
{
	return map_lookup_elem(map, tuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 70,
  "endLine": 83,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "__snat_update",
  "developer_inline_comments": [],
  "updateMaps": [
    " map"
  ],
  "readMaps": [],
  "input": [
    "const void *map",
    " const void *otuple",
    " const void *ostate",
    " const void *rtuple",
    " const void *rstate"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "map_delete_elem",
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
    "static __always_inline __maybe_unused int __snat_update (const void *map, const void *otuple, const void *ostate, const void *rtuple, const void *rstate)\n",
    "{\n",
    "    int ret;\n",
    "    ret = map_update_elem (map, rtuple, rstate, BPF_NOEXIST);\n",
    "    if (!ret) {\n",
    "        ret = map_update_elem (map, otuple, ostate, BPF_NOEXIST);\n",
    "        if (ret)\n",
    "            map_delete_elem (map, rtuple);\n",
    "    }\n",
    "    return ret;\n",
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
static __always_inline __maybe_unused int
__snat_update(const void *map, const void *otuple, const void *ostate,
	      const void *rtuple, const void *rstate)
{
	int ret;

	ret = map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
	if (!ret) {
		ret = map_update_elem(map, otuple, ostate, BPF_NOEXIST);
		if (ret)
			map_delete_elem(map, rtuple);
	}
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 85,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "__snat_delete",
  "developer_inline_comments": [],
  "updateMaps": [
    " map"
  ],
  "readMaps": [],
  "input": [
    "const void *map",
    " const void *otuple",
    " const void *rtuple"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "map_delete_elem"
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
    "static __always_inline __maybe_unused void __snat_delete (const void *map, const void *otuple, const void *rtuple)\n",
    "{\n",
    "    map_delete_elem (map, otuple);\n",
    "    map_delete_elem (map, rtuple);\n",
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
static __always_inline __maybe_unused void
__snat_delete(const void *map, const void *otuple, const void *rtuple)
{
	map_delete_elem(map, otuple);
	map_delete_elem(map, rtuple);
}

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct ipv4_nat_target {
	__be32 addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
};

#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV4 __section_maps_btf;

#ifdef ENABLE_IP_MASQ_AGENT
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IP_MASQ_AGENT_IPV4 __section_maps_btf;
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 136,
  "endLine": 140,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_lookup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *tuple"
  ],
  "output": "static__always_inlinestructipv4_nat_entry",
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
    "static __always_inline struct ipv4_nat_entry *snat_v4_lookup (const struct ipv4_ct_tuple *tuple)\n",
    "{\n",
    "    return __snat_lookup (&SNAT_MAPPING_IPV4, tuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_lookup"
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
struct ipv4_nat_entry *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 142,
  "endLine": 149,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_update",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *otuple",
    " const struct ipv4_nat_entry *ostate",
    " const struct ipv4_ct_tuple *rtuple",
    " const struct ipv4_nat_entry *rstate"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v4_update (const struct ipv4_ct_tuple *otuple, const struct ipv4_nat_entry *ostate, const struct ipv4_ct_tuple *rtuple, const struct ipv4_nat_entry *rstate)\n",
    "{\n",
    "    return __snat_update (&SNAT_MAPPING_IPV4, otuple, ostate, rtuple, rstate);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_update"
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
static __always_inline int snat_v4_update(const struct ipv4_ct_tuple *otuple,
					  const struct ipv4_nat_entry *ostate,
					  const struct ipv4_ct_tuple *rtuple,
					  const struct ipv4_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate,
			     rtuple, rstate);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 151,
  "endLine": 155,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_delete",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *otuple",
    " const struct ipv4_ct_tuple *rtuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v4_delete (const struct ipv4_ct_tuple *otuple, const struct ipv4_ct_tuple *rtuple)\n",
    "{\n",
    "    __snat_delete (&SNAT_MAPPING_IPV4, otuple, rtuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_delete"
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
static __always_inline void snat_v4_delete(const struct ipv4_ct_tuple *otuple,
					   const struct ipv4_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV4, otuple, rtuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 157,
  "endLine": 168,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_swap_tuple",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *otuple",
    " struct ipv4_ct_tuple *rtuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v4_swap_tuple (const struct ipv4_ct_tuple *otuple, struct ipv4_ct_tuple *rtuple)\n",
    "{\n",
    "    memset (rtuple, 0, sizeof (*rtuple));\n",
    "    rtuple->nexthdr = otuple->nexthdr;\n",
    "    rtuple->daddr = otuple->saddr;\n",
    "    rtuple->saddr = otuple->daddr;\n",
    "    rtuple->dport = otuple->sport;\n",
    "    rtuple->sport = otuple->dport;\n",
    "    rtuple->flags = otuple->flags == NAT_DIR_EGRESS ? NAT_DIR_INGRESS : NAT_DIR_EGRESS;\n",
    "}\n"
  ],
  "called_function_list": [
    "memset"
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
static __always_inline void snat_v4_swap_tuple(const struct ipv4_ct_tuple *otuple,
					       struct ipv4_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 170,
  "endLine": 183,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_reverse_tuple",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple *otuple",
    " struct ipv4_ct_tuple *rtuple"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v4_reverse_tuple (const struct ipv4_ct_tuple *otuple, struct ipv4_ct_tuple *rtuple)\n",
    "{\n",
    "    struct ipv4_nat_entry *ostate;\n",
    "    ostate = snat_v4_lookup (otuple);\n",
    "    if (ostate) {\n",
    "        snat_v4_swap_tuple (otuple, rtuple);\n",
    "        rtuple->daddr = ostate->to_saddr;\n",
    "        rtuple->dport = ostate->to_sport;\n",
    "    }\n",
    "    return ostate ? 0 : -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v4_swap_tuple",
    "snat_v4_lookup"
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
static __always_inline int snat_v4_reverse_tuple(const struct ipv4_ct_tuple *otuple,
						 struct ipv4_ct_tuple *rtuple)
{
	struct ipv4_nat_entry *ostate;

	ostate = snat_v4_lookup(otuple);
	if (ostate) {
		snat_v4_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 185,
  "endLine": 193,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_ct_canonicalize",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv4_ct_tuple *otuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v4_ct_canonicalize (struct ipv4_ct_tuple *otuple)\n",
    "{\n",
    "    __be32 addr = otuple->saddr;\n",
    "    otuple->flags = NAT_DIR_EGRESS;\n",
    "    otuple->saddr = otuple->daddr;\n",
    "    otuple->daddr = addr;\n",
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
static __always_inline void snat_v4_ct_canonicalize(struct ipv4_ct_tuple *otuple)
{
	__be32 addr = otuple->saddr;

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	otuple->saddr = otuple->daddr;
	otuple->daddr = addr;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 195,
  "endLine": 204,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_delete_tuples",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv4_ct_tuple *otuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v4_delete_tuples (struct ipv4_ct_tuple *otuple)\n",
    "{\n",
    "    struct ipv4_ct_tuple rtuple;\n",
    "    if (otuple->flags & TUPLE_F_IN)\n",
    "        return;\n",
    "    snat_v4_ct_canonicalize (otuple);\n",
    "    if (!snat_v4_reverse_tuple (otuple, &rtuple))\n",
    "        snat_v4_delete (otuple, &rtuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v4_ct_canonicalize",
    "snat_v4_reverse_tuple",
    "snat_v4_delete"
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
static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *otuple)
{
	struct ipv4_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v4_ct_canonicalize(otuple);
	if (!snat_v4_reverse_tuple(otuple, &rtuple))
		snat_v4_delete(otuple, &rtuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 206,
  "endLine": 258,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_new_mapping",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv4_ct_tuple *otuple",
    " struct ipv4_nat_entry *ostate",
    " const struct ipv4_nat_target *target"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "send_signal",
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "perf_event",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int snat_v4_new_mapping (struct  __ctx_buff *ctx, struct ipv4_ct_tuple *otuple, struct ipv4_nat_entry *ostate, const struct ipv4_nat_target *target)\n",
    "{\n",
    "    int ret = DROP_NAT_NO_MAPPING, retries;\n",
    "    struct ipv4_nat_entry rstate;\n",
    "    struct ipv4_ct_tuple rtuple;\n",
    "    __u16 port;\n",
    "    memset (&rstate, 0, sizeof (rstate));\n",
    "    memset (ostate, 0, sizeof (*ostate));\n",
    "    rstate.to_daddr = otuple->saddr;\n",
    "    rstate.to_dport = otuple->sport;\n",
    "    ostate->to_saddr = target->addr;\n",
    "    snat_v4_swap_tuple (otuple, &rtuple);\n",
    "    port = __snat_try_keep_port (target -> min_port, target -> max_port, bpf_ntohs (otuple -> sport));\n",
    "    rtuple.dport = ostate->to_sport = bpf_htons (port);\n",
    "    rtuple.daddr = target->addr;\n",
    "    if (otuple->saddr == target->addr) {\n",
    "        ostate->common.host_local = 1;\n",
    "        rstate.common.host_local = ostate->common.host_local;\n",
    "    }\n",
    "\n",
    "#pragma unroll\n",
    "    for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {\n",
    "        if (!snat_v4_lookup (&rtuple)) {\n",
    "            ostate->common.created = bpf_mono_now ();\n",
    "            rstate.common.created = ostate->common.created;\n",
    "            ret = snat_v4_update (otuple, ostate, & rtuple, & rstate);\n",
    "            if (!ret)\n",
    "                break;\n",
    "        }\n",
    "        port = __snat_clamp_port_range (target -> min_port, target -> max_port, retries ? port + 1 : (__u16) get_prandom_u32 ());\n",
    "        rtuple.dport = ostate->to_sport = bpf_htons (port);\n",
    "    }\n",
    "    if (retries > SNAT_SIGNAL_THRES)\n",
    "        send_signal_nat_fill_up (ctx, SIGNAL_PROTO_V4);\n",
    "    return !ret ? 0 : DROP_NAT_NO_MAPPING;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "__snat_try_keep_port",
    "snat_v4_update",
    "bpf_mono_now",
    "snat_v4_swap_tuple",
    "send_signal_nat_fill_up",
    "snat_v4_lookup",
    "__snat_clamp_port_range",
    "bpf_htons",
    "memset"
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
static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv4_nat_entry rstate;
	struct ipv4_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v4_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	if (otuple->saddr == target->addr) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v4_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V4);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 260,
  "endLine": 299,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_track_local",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct ipv4_ct_tuple *tuple",
    " const struct ipv4_nat_entry *state",
    " enum nat_dir dir",
    " __u32 off",
    " const struct ipv4_nat_target *target"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v4_track_local (struct  __ctx_buff *ctx, const struct ipv4_ct_tuple *tuple, const struct ipv4_nat_entry *state, enum nat_dir dir, __u32 off, const struct ipv4_nat_target *target)\n",
    "{\n",
    "    struct ct_state ct_state;\n",
    "    struct ipv4_ct_tuple tmp;\n",
    "    bool needs_ct = false;\n",
    "    __u32 monitor = 0;\n",
    "    enum ct_dir where;\n",
    "    int ret;\n",
    "    if (state && state->common.host_local) {\n",
    "        needs_ct = true;\n",
    "    }\n",
    "    else if (!state && dir == NAT_DIR_EGRESS) {\n",
    "        if (tuple->saddr == target->addr)\n",
    "            needs_ct = true;\n",
    "    }\n",
    "    if (!needs_ct)\n",
    "        return 0;\n",
    "    memset (&ct_state, 0, sizeof (ct_state));\n",
    "    memcpy (&tmp, tuple, sizeof (tmp));\n",
    "    where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;\n",
    "    ret = ct_lookup4 (get_ct_map4 (& tmp), & tmp, ctx, off, where, & ct_state, & monitor);\n",
    "    if (ret < 0) {\n",
    "        return ret;\n",
    "    }\n",
    "    else if (ret == CT_NEW) {\n",
    "        ret = ct_create4 (get_ct_map4 (& tmp), NULL, & tmp, ctx, where, & ct_state, false, false);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "ct_lookup4",
    "get_ct_map4",
    "ct_create4",
    "IS_ERR",
    "memset"
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
static __always_inline int snat_v4_track_local(struct __ctx_buff *ctx,
					       const struct ipv4_ct_tuple *tuple,
					       const struct ipv4_nat_entry *state,
					       enum nat_dir dir, __u32 off,
					       const struct ipv4_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv4_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	enum ct_dir where;
	int ret;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (tuple->saddr == target->addr)
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup4(get_ct_map4(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create4(get_ct_map4(&tmp), NULL, &tmp, ctx,
				 where, &ct_state, false, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 301,
  "endLine": 322,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_handle_mapping",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv4_ct_tuple *tuple",
    " struct ipv4_nat_entry **state",
    " struct ipv4_nat_entry *tmp",
    " enum nat_dir dir",
    " __u32 off",
    " const struct ipv4_nat_target *target"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v4_handle_mapping (struct  __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, struct ipv4_nat_entry **state, struct ipv4_nat_entry *tmp, enum nat_dir dir, __u32 off, const struct ipv4_nat_target *target)\n",
    "{\n",
    "    int ret;\n",
    "    *state = snat_v4_lookup (tuple);\n",
    "    ret = snat_v4_track_local (ctx, tuple, * state, dir, off, target);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    else if (*state)\n",
    "        return NAT_CONTINUE_XLATE;\n",
    "    else if (dir == NAT_DIR_INGRESS)\n",
    "        return tuple->nexthdr != IPPROTO_ICMP && bpf_ntohs (tuple->dport) < target->min_port ? NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;\n",
    "    else\n",
    "        return snat_v4_new_mapping (ctx, tuple, (*state = tmp), target);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "snat_v4_lookup",
    "snat_v4_track_local",
    "snat_v4_new_mapping"
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
static __always_inline int snat_v4_handle_mapping(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry **state,
						  struct ipv4_nat_entry *tmp,
						  enum nat_dir dir, __u32 off,
						  const struct ipv4_nat_target *target)
{
	int ret;

	*state = snat_v4_lookup(tuple);
	ret = snat_v4_track_local(ctx, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMP &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
		return snat_v4_new_mapping(ctx, tuple, (*state = tmp), target);
}

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
  "startLine": 324,
  "endLine": 380,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_rewrite_egress",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv4_ct_tuple *tuple",
    " struct ipv4_nat_entry *state",
    " __u32 off",
    " bool has_l4_header"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "lwt_in",
    "sched_act",
    "lwt_out",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline int snat_v4_rewrite_egress (struct  __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, struct ipv4_nat_entry *state, __u32 off, bool has_l4_header)\n",
    "{\n",
    "    int ret, flags = BPF_F_PSEUDO_HDR;\n",
    "    struct csum_offset csum = {}\n",
    "    ;\n",
    "    __be32 sum_l4 = 0, sum;\n",
    "    if (state->to_saddr == tuple->saddr && state->to_sport == tuple->sport)\n",
    "        return 0;\n",
    "    sum = csum_diff (& tuple -> saddr, 4, & state -> to_saddr, 4, 0);\n",
    "    if (has_l4_header) {\n",
    "        csum_l4_offset_and_flags (tuple->nexthdr, &csum);\n",
    "        if (state->to_sport != tuple->sport) {\n",
    "            switch (tuple->nexthdr) {\n",
    "            case IPPROTO_TCP :\n",
    "            case IPPROTO_UDP :\n",
    "                ret = l4_modify_port (ctx, off, offsetof (struct tcphdr, source), &csum, state->to_sport, tuple->sport);\n",
    "                if (ret < 0)\n",
    "                    return ret;\n",
    "                break;\n",
    "            case IPPROTO_ICMP :\n",
    "                {\n",
    "                    __be32 from, to;\n",
    "                    if (ctx_store_bytes (ctx, off + offsetof (struct icmphdr, un.echo.id), &state->to_sport, sizeof (state->to_sport), 0) < 0)\n",
    "                        return DROP_WRITE_ERROR;\n",
    "                    from = tuple->sport;\n",
    "                    to = state->to_sport;\n",
    "                    flags = 0;\n",
    "                    sum_l4 = csum_diff (& from, 4, & to, 4, 0);\n",
    "                    csum.offset = offsetof (struct icmphdr, checksum);\n",
    "                    break;\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct iphdr, saddr), &state->to_saddr, 4, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (l3_csum_replace (ctx, ETH_HLEN + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    if (tuple->nexthdr == IPPROTO_ICMP)\n",
    "        sum = sum_l4;\n",
    "    if (csum.offset && csum_l4_replace (ctx, off, &csum, 0, sum, flags) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "offsetof",
    "csum_l4_offset_and_flags",
    "ctx_store_bytes",
    "csum_l4_replace"
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
static __always_inline int snat_v4_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 off, bool has_l4_header)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	if (has_l4_header) {
		csum_l4_offset_and_flags(tuple->nexthdr, &csum);

		if (state->to_sport != tuple->sport) {
			switch (tuple->nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				ret = l4_modify_port(ctx, off,
						     offsetof(struct tcphdr, source),
						     &csum, state->to_sport,
						     tuple->sport);
				if (ret < 0)
					return ret;
				break;
			case IPPROTO_ICMP: {
				__be32 from, to;

				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_sport,
						    sizeof(state->to_sport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->sport;
				to = state->to_sport;
				flags = 0; /* ICMPv4 has no pseudo-header */
				sum_l4 = csum_diff(&from, 4, &to, 4, 0);
				csum.offset = offsetof(struct icmphdr, checksum);
				break;
			}}
		}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

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
  "startLine": 382,
  "endLine": 435,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_rewrite_ingress",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv4_ct_tuple *tuple",
    " struct ipv4_nat_entry *state",
    " __u32 off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "lwt_in",
    "sched_act",
    "lwt_out",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline int snat_v4_rewrite_ingress (struct  __ctx_buff *ctx, struct ipv4_ct_tuple *tuple, struct ipv4_nat_entry *state, __u32 off)\n",
    "{\n",
    "    int ret, flags = BPF_F_PSEUDO_HDR;\n",
    "    struct csum_offset csum = {}\n",
    "    ;\n",
    "    __be32 sum_l4 = 0, sum;\n",
    "    if (state->to_daddr == tuple->daddr && state->to_dport == tuple->dport)\n",
    "        return 0;\n",
    "    sum = csum_diff (& tuple -> daddr, 4, & state -> to_daddr, 4, 0);\n",
    "    csum_l4_offset_and_flags (tuple->nexthdr, &csum);\n",
    "    if (state->to_dport != tuple->dport) {\n",
    "        switch (tuple->nexthdr) {\n",
    "        case IPPROTO_TCP :\n",
    "        case IPPROTO_UDP :\n",
    "            ret = l4_modify_port (ctx, off, offsetof (struct tcphdr, dest), &csum, state->to_dport, tuple->dport);\n",
    "            if (ret < 0)\n",
    "                return ret;\n",
    "            break;\n",
    "        case IPPROTO_ICMP :\n",
    "            {\n",
    "                __be32 from, to;\n",
    "                if (ctx_store_bytes (ctx, off + offsetof (struct icmphdr, un.echo.id), &state->to_dport, sizeof (state->to_dport), 0) < 0)\n",
    "                    return DROP_WRITE_ERROR;\n",
    "                from = tuple->dport;\n",
    "                to = state->to_dport;\n",
    "                flags = 0;\n",
    "                sum_l4 = csum_diff (& from, 4, & to, 4, 0);\n",
    "                csum.offset = offsetof (struct icmphdr, checksum);\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct iphdr, daddr), &state->to_daddr, 4, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (l3_csum_replace (ctx, ETH_HLEN + offsetof (struct iphdr, check), 0, sum, 0) < 0)\n",
    "        return DROP_CSUM_L3;\n",
    "    if (tuple->nexthdr == IPPROTO_ICMP)\n",
    "        sum = sum_l4;\n",
    "    if (csum.offset && csum_l4_replace (ctx, off, &csum, 0, sum, flags) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "offsetof",
    "csum_l4_offset_and_flags",
    "ctx_store_bytes",
    "csum_l4_replace"
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
static __always_inline int snat_v4_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv4_ct_tuple *tuple,
						   struct ipv4_nat_entry *state,
						   __u32 off)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmphdr, un.echo.id),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			flags = 0; /* ICMPv4 has no pseudo-header */
			sum_l4 = csum_diff(&from, 4, &to, 4, 0);
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 437,
  "endLine": 452,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_can_skip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_nat_target *target",
    " const struct ipv4_ct_tuple *tuple",
    " enum nat_dir dir",
    " bool from_endpoint",
    " bool icmp_echoreply"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool snat_v4_can_skip (const struct ipv4_nat_target *target, const struct ipv4_ct_tuple *tuple, enum nat_dir dir, bool from_endpoint, bool icmp_echoreply)\n",
    "{\n",
    "    __u16 dport = bpf_ntohs (tuple->dport), sport = bpf_ntohs (tuple->sport);\n",
    "    if (dir == NAT_DIR_EGRESS && ((!from_endpoint && !target->src_from_world && sport < NAT_MIN_EGRESS) || icmp_echoreply))\n",
    "        return true;\n",
    "    if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))\n",
    "        return true;\n",
    "    return false;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs"
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
static __always_inline bool
snat_v4_can_skip(const struct ipv4_nat_target *target,
		 const struct ipv4_ct_tuple *tuple, enum nat_dir dir,
		 bool from_endpoint, bool icmp_echoreply)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	if (dir == NAT_DIR_EGRESS &&
	    ((!from_endpoint && !target->src_from_world && sport < NAT_MIN_EGRESS) ||
	     icmp_echoreply))
		return true;
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;

	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    },
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
  "startLine": 454,
  "endLine": 505,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_create_dsr",
  "developer_inline_comments": [],
  "updateMaps": [
    "  SNAT_MAPPING_IPV4"
  ],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __be32 to_saddr",
    " __be16 to_sport"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "map_update_elem",
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v4_create_dsr (struct  __ctx_buff *ctx, __be32 to_saddr, __be16 to_sport)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    struct ipv4_nat_entry state = {}\n",
    "    ;\n",
    "    struct iphdr *ip4;\n",
    "    struct {\n",
    "        __be16 sport;\n",
    "        __be16 dport;\n",
    "    } l4hdr;\n",
    "\n",
    "    __u32 off;\n",
    "    int ret;\n",
    "    build_bug_on (sizeof (struct ipv4_nat_entry) > 64);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip4->protocol;\n",
    "    tuple.daddr = ip4->saddr;\n",
    "    tuple.saddr = ip4->daddr;\n",
    "    tuple.flags = NAT_DIR_EGRESS;\n",
    "    off = ((void *) ip4 - data) + ipv4_hdrlen (ip4);\n",
    "    switch (tuple.nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "        if (ctx_load_bytes (ctx, off, &l4hdr, sizeof (l4hdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        tuple.dport = l4hdr.sport;\n",
    "        tuple.sport = l4hdr.dport;\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_NAT_UNSUPP_PROTO;\n",
    "    }\n",
    "    state.common.created = bpf_mono_now ();\n",
    "    state.to_saddr = to_saddr;\n",
    "    state.to_sport = to_sport;\n",
    "    ret = map_update_elem (& SNAT_MAPPING_IPV4, & tuple, & state, 0);\n",
    "    if (ret)\n",
    "        return ret;\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "bpf_mono_now",
    "build_bug_on",
    "ipv4_hdrlen",
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
static __always_inline __maybe_unused int snat_v4_create_dsr(struct __ctx_buff *ctx,
							     __be32 to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry state = {};
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->saddr;
	tuple.saddr = ip4->daddr;
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	state.to_saddr = to_saddr;
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV4, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
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
  "startLine": 507,
  "endLine": 572,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " enum nat_dir dir",
    " const struct ipv4_nat_target *target",
    " bool from_endpoint"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v4_process (struct  __ctx_buff *ctx, enum nat_dir dir, const struct ipv4_nat_target *target, bool from_endpoint)\n",
    "{\n",
    "    struct icmphdr icmphdr __align_stack_8;\n",
    "    struct ipv4_nat_entry *state, tmp;\n",
    "    struct ipv4_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    struct {\n",
    "        __be16 sport;\n",
    "        __be16 dport;\n",
    "    } l4hdr;\n",
    "\n",
    "    bool icmp_echoreply = false;\n",
    "    __u64 off;\n",
    "    int ret;\n",
    "    build_bug_on (sizeof (struct ipv4_nat_entry) > 64);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip4->protocol;\n",
    "    tuple.daddr = ip4->daddr;\n",
    "    tuple.saddr = ip4->saddr;\n",
    "    tuple.flags = dir;\n",
    "    off = ((void *) ip4 - data) + ipv4_hdrlen (ip4);\n",
    "    switch (tuple.nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "        if (ctx_load_bytes (ctx, off, &l4hdr, sizeof (l4hdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        tuple.dport = l4hdr.dport;\n",
    "        tuple.sport = l4hdr.sport;\n",
    "        break;\n",
    "    case IPPROTO_ICMP :\n",
    "        if (ctx_load_bytes (ctx, off, &icmphdr, sizeof (icmphdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        if (icmphdr.type != ICMP_ECHO && icmphdr.type != ICMP_ECHOREPLY)\n",
    "            return DROP_NAT_UNSUPP_PROTO;\n",
    "        if (icmphdr.type == ICMP_ECHO) {\n",
    "            tuple.dport = 0;\n",
    "            tuple.sport = icmphdr.un.echo.id;\n",
    "        }\n",
    "        else {\n",
    "            tuple.dport = icmphdr.un.echo.id;\n",
    "            tuple.sport = 0;\n",
    "            icmp_echoreply = true;\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        return NAT_PUNT_TO_STACK;\n",
    "    }\n",
    "    if (snat_v4_can_skip (target, &tuple, dir, from_endpoint, icmp_echoreply))\n",
    "        return NAT_PUNT_TO_STACK;\n",
    "    ret = snat_v4_handle_mapping (ctx, & tuple, & state, & tmp, dir, off, target);\n",
    "    if (ret > 0)\n",
    "        return CTX_ACT_OK;\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    return dir == NAT_DIR_EGRESS ? snat_v4_rewrite_egress (ctx, &tuple, state, off, ipv4_has_l4_header (ip4)) : snat_v4_rewrite_ingress (ctx, &tuple, state, off);\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "snat_v4_handle_mapping",
    "build_bug_on",
    "snat_v4_rewrite_ingress",
    "ipv4_has_l4_header",
    "ipv4_hdrlen",
    "ctx_load_bytes",
    "snat_v4_rewrite_egress",
    "snat_v4_can_skip"
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
static __always_inline __maybe_unused int
snat_v4_process(struct __ctx_buff *ctx, enum nat_dir dir,
		const struct ipv4_nat_target *target, bool from_endpoint)
{
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state, tmp;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	bool icmp_echoreply = false;
	__u64 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->daddr;
	tuple.saddr = ip4->saddr;
	tuple.flags = dir;
	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		if (icmphdr.type != ICMP_ECHO &&
		    icmphdr.type != ICMP_ECHOREPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmphdr.type == ICMP_ECHO) {
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
		} else {
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_can_skip(target, &tuple, dir, from_endpoint, icmp_echoreply))
		return NAT_PUNT_TO_STACK;
	ret = snat_v4_handle_mapping(ctx, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return dir == NAT_DIR_EGRESS ?
	       snat_v4_rewrite_egress(ctx, &tuple, state, off, ipv4_has_l4_header(ip4)) :
	       snat_v4_rewrite_ingress(ctx, &tuple, state, off);
}
#else
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
  "startLine": 574,
  "endLine": 581,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " enum nat_dir dir __maybe_unused",
    " const struct ipv4_nat_target * target __maybe_unused",
    " bool from_endpoint __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v4_process (struct  __ctx_buff * ctx __maybe_unused, enum nat_dir dir __maybe_unused, const struct ipv4_nat_target * target __maybe_unused, bool from_endpoint __maybe_unused)\n",
    "{\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "snat_v4_handle_mapping",
    "build_bug_on",
    "snat_v4_rewrite_ingress",
    "ipv4_has_l4_header",
    "ipv4_hdrlen",
    "ctx_load_bytes",
    "snat_v4_rewrite_egress",
    "snat_v4_can_skip"
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
static __always_inline __maybe_unused
int snat_v4_process(struct __ctx_buff *ctx __maybe_unused,
		    enum nat_dir dir __maybe_unused,
		    const struct ipv4_nat_target *target __maybe_unused,
		    bool from_endpoint __maybe_unused)
{
	return CTX_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 583,
  "endLine": 586,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v4_delete_tuples",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv4_ct_tuple * tuple __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void snat_v4_delete_tuples (struct ipv4_ct_tuple * tuple __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v4_ct_canonicalize",
    "snat_v4_reverse_tuple",
    "snat_v4_delete"
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
static __always_inline __maybe_unused
void snat_v4_delete_tuples(struct ipv4_ct_tuple *tuple __maybe_unused)
{
}
#endif

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
		struct {
			union v6addr to_saddr;
			__be16       to_sport;
		};
		struct {
			union v6addr to_daddr;
			__be16       to_dport;
		};
	};
};

struct ipv6_nat_target {
	union v6addr addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
};

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ipv6_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV6 __section_maps_btf;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 622,
  "endLine": 626,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_lookup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple *tuple"
  ],
  "output": "static__always_inlinestructipv6_nat_entry",
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
    "static __always_inline struct ipv6_nat_entry *snat_v6_lookup (struct ipv6_ct_tuple *tuple)\n",
    "{\n",
    "    return __snat_lookup (&SNAT_MAPPING_IPV6, tuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_lookup"
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
struct ipv6_nat_entry *snat_v6_lookup(struct ipv6_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV6, tuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 628,
  "endLine": 635,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_update",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple *otuple",
    " struct ipv6_nat_entry *ostate",
    " struct ipv6_ct_tuple *rtuple",
    " struct ipv6_nat_entry *rstate"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v6_update (struct ipv6_ct_tuple *otuple, struct ipv6_nat_entry *ostate, struct ipv6_ct_tuple *rtuple, struct ipv6_nat_entry *rstate)\n",
    "{\n",
    "    return __snat_update (&SNAT_MAPPING_IPV6, otuple, ostate, rtuple, rstate);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_update"
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
static __always_inline int snat_v6_update(struct ipv6_ct_tuple *otuple,
					  struct ipv6_nat_entry *ostate,
					  struct ipv6_ct_tuple *rtuple,
					  struct ipv6_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV6, otuple, ostate,
			     rtuple, rstate);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 637,
  "endLine": 641,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_delete",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6_ct_tuple *otuple",
    " const struct ipv6_ct_tuple *rtuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v6_delete (const struct ipv6_ct_tuple *otuple, const struct ipv6_ct_tuple *rtuple)\n",
    "{\n",
    "    __snat_delete (&SNAT_MAPPING_IPV6, otuple, rtuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "__snat_delete"
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
static __always_inline void snat_v6_delete(const struct ipv6_ct_tuple *otuple,
					   const struct ipv6_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV6, otuple, rtuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 643,
  "endLine": 654,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_swap_tuple",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6_ct_tuple *otuple",
    " struct ipv6_ct_tuple *rtuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v6_swap_tuple (const struct ipv6_ct_tuple *otuple, struct ipv6_ct_tuple *rtuple)\n",
    "{\n",
    "    memset (rtuple, 0, sizeof (*rtuple));\n",
    "    rtuple->nexthdr = otuple->nexthdr;\n",
    "    rtuple->daddr = otuple->saddr;\n",
    "    rtuple->saddr = otuple->daddr;\n",
    "    rtuple->dport = otuple->sport;\n",
    "    rtuple->sport = otuple->dport;\n",
    "    rtuple->flags = otuple->flags == NAT_DIR_EGRESS ? NAT_DIR_INGRESS : NAT_DIR_EGRESS;\n",
    "}\n"
  ],
  "called_function_list": [
    "memset"
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
static __always_inline void snat_v6_swap_tuple(const struct ipv6_ct_tuple *otuple,
					       struct ipv6_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 656,
  "endLine": 669,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_reverse_tuple",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple *otuple",
    " struct ipv6_ct_tuple *rtuple"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v6_reverse_tuple (struct ipv6_ct_tuple *otuple, struct ipv6_ct_tuple *rtuple)\n",
    "{\n",
    "    struct ipv6_nat_entry *ostate;\n",
    "    ostate = snat_v6_lookup (otuple);\n",
    "    if (ostate) {\n",
    "        snat_v6_swap_tuple (otuple, rtuple);\n",
    "        rtuple->daddr = ostate->to_saddr;\n",
    "        rtuple->dport = ostate->to_sport;\n",
    "    }\n",
    "    return ostate ? 0 : -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v6_swap_tuple",
    "snat_v6_lookup"
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
static __always_inline int snat_v6_reverse_tuple(struct ipv6_ct_tuple *otuple,
						 struct ipv6_ct_tuple *rtuple)
{
	struct ipv6_nat_entry *ostate;

	ostate = snat_v6_lookup(otuple);
	if (ostate) {
		snat_v6_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 671,
  "endLine": 680,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_ct_canonicalize",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple *otuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v6_ct_canonicalize (struct ipv6_ct_tuple *otuple)\n",
    "{\n",
    "    union v6addr addr = {}\n",
    "    ;\n",
    "    otuple->flags = NAT_DIR_EGRESS;\n",
    "    ipv6_addr_copy (&addr, &otuple->saddr);\n",
    "    ipv6_addr_copy (&otuple->saddr, &otuple->daddr);\n",
    "    ipv6_addr_copy (&otuple->daddr, &addr);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __always_inline void snat_v6_ct_canonicalize(struct ipv6_ct_tuple *otuple)
{
	union v6addr addr = {};

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	ipv6_addr_copy(&addr, &otuple->saddr);
	ipv6_addr_copy(&otuple->saddr, &otuple->daddr);
	ipv6_addr_copy(&otuple->daddr, &addr);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 682,
  "endLine": 691,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_delete_tuples",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple *otuple"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void snat_v6_delete_tuples (struct ipv6_ct_tuple *otuple)\n",
    "{\n",
    "    struct ipv6_ct_tuple rtuple;\n",
    "    if (otuple->flags & TUPLE_F_IN)\n",
    "        return;\n",
    "    snat_v6_ct_canonicalize (otuple);\n",
    "    if (!snat_v6_reverse_tuple (otuple, &rtuple))\n",
    "        snat_v6_delete (otuple, &rtuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v6_ct_canonicalize",
    "snat_v6_reverse_tuple",
    "snat_v6_delete"
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
static __always_inline void snat_v6_delete_tuples(struct ipv6_ct_tuple *otuple)
{
	struct ipv6_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v6_ct_canonicalize(otuple);
	if (!snat_v6_reverse_tuple(otuple, &rtuple))
		snat_v6_delete(otuple, &rtuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 693,
  "endLine": 745,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_new_mapping",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6_ct_tuple *otuple",
    " struct ipv6_nat_entry *ostate",
    " const struct ipv6_nat_target *target"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "send_signal",
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "perf_event",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int snat_v6_new_mapping (struct  __ctx_buff *ctx, struct ipv6_ct_tuple *otuple, struct ipv6_nat_entry *ostate, const struct ipv6_nat_target *target)\n",
    "{\n",
    "    int ret = DROP_NAT_NO_MAPPING, retries;\n",
    "    struct ipv6_nat_entry rstate;\n",
    "    struct ipv6_ct_tuple rtuple;\n",
    "    __u16 port;\n",
    "    memset (&rstate, 0, sizeof (rstate));\n",
    "    memset (ostate, 0, sizeof (*ostate));\n",
    "    rstate.to_daddr = otuple->saddr;\n",
    "    rstate.to_dport = otuple->sport;\n",
    "    ostate->to_saddr = target->addr;\n",
    "    snat_v6_swap_tuple (otuple, &rtuple);\n",
    "    port = __snat_try_keep_port (target -> min_port, target -> max_port, bpf_ntohs (otuple -> sport));\n",
    "    rtuple.dport = ostate->to_sport = bpf_htons (port);\n",
    "    rtuple.daddr = target->addr;\n",
    "    if (!ipv6_addrcmp (&otuple->saddr, &rtuple.daddr)) {\n",
    "        ostate->common.host_local = 1;\n",
    "        rstate.common.host_local = ostate->common.host_local;\n",
    "    }\n",
    "\n",
    "#pragma unroll\n",
    "    for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {\n",
    "        if (!snat_v6_lookup (&rtuple)) {\n",
    "            ostate->common.created = bpf_mono_now ();\n",
    "            rstate.common.created = ostate->common.created;\n",
    "            ret = snat_v6_update (otuple, ostate, & rtuple, & rstate);\n",
    "            if (!ret)\n",
    "                break;\n",
    "        }\n",
    "        port = __snat_clamp_port_range (target -> min_port, target -> max_port, retries ? port + 1 : (__u16) get_prandom_u32 ());\n",
    "        rtuple.dport = ostate->to_sport = bpf_htons (port);\n",
    "    }\n",
    "    if (retries > SNAT_SIGNAL_THRES)\n",
    "        send_signal_nat_fill_up (ctx, SIGNAL_PROTO_V6);\n",
    "    return !ret ? 0 : DROP_NAT_NO_MAPPING;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "snat_v6_lookup",
    "__snat_try_keep_port",
    "bpf_mono_now",
    "snat_v6_update",
    "send_signal_nat_fill_up",
    "__snat_clamp_port_range",
    "ipv6_addrcmp",
    "snat_v6_swap_tuple",
    "bpf_htons",
    "memset"
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
static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv6_nat_entry rstate;
	struct ipv6_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v6_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	if (!ipv6_addrcmp(&otuple->saddr, &rtuple.daddr)) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v6_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V6);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 747,
  "endLine": 785,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_track_local",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6_ct_tuple *tuple",
    " const struct ipv6_nat_entry *state",
    " enum nat_dir dir",
    " __u32 off",
    " const struct ipv6_nat_target *target"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v6_track_local (struct  __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, const struct ipv6_nat_entry *state, enum nat_dir dir, __u32 off, const struct ipv6_nat_target *target)\n",
    "{\n",
    "    struct ct_state ct_state;\n",
    "    struct ipv6_ct_tuple tmp;\n",
    "    bool needs_ct = false;\n",
    "    __u32 monitor = 0;\n",
    "    int ret, where;\n",
    "    if (state && state->common.host_local) {\n",
    "        needs_ct = true;\n",
    "    }\n",
    "    else if (!state && dir == NAT_DIR_EGRESS) {\n",
    "        if (!ipv6_addrcmp (&tuple->saddr, (void *) &target->addr))\n",
    "            needs_ct = true;\n",
    "    }\n",
    "    if (!needs_ct)\n",
    "        return 0;\n",
    "    memset (&ct_state, 0, sizeof (ct_state));\n",
    "    memcpy (&tmp, tuple, sizeof (tmp));\n",
    "    where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;\n",
    "    ret = ct_lookup6 (get_ct_map6 (& tmp), & tmp, ctx, off, where, & ct_state, & monitor);\n",
    "    if (ret < 0) {\n",
    "        return ret;\n",
    "    }\n",
    "    else if (ret == CT_NEW) {\n",
    "        ret = ct_create6 (get_ct_map6 (& tmp), NULL, & tmp, ctx, where, & ct_state, false, false);\n",
    "        if (IS_ERR (ret))\n",
    "            return ret;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "ct_create6",
    "ct_lookup6",
    "get_ct_map6",
    "ipv6_addrcmp",
    "IS_ERR",
    "memset"
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
static __always_inline int snat_v6_track_local(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *tuple,
					       const struct ipv6_nat_entry *state,
					       enum nat_dir dir, __u32 off,
					       const struct ipv6_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv6_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	int ret, where;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (!ipv6_addrcmp(&tuple->saddr, (void *)&target->addr))
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup6(get_ct_map6(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create6(get_ct_map6(&tmp), NULL, &tmp, ctx, where,
				 &ct_state, false, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 787,
  "endLine": 808,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_handle_mapping",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6_ct_tuple *tuple",
    " struct ipv6_nat_entry **state",
    " struct ipv6_nat_entry *tmp",
    " enum nat_dir dir",
    " __u32 off",
    " const struct ipv6_nat_target *target"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int snat_v6_handle_mapping (struct  __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, struct ipv6_nat_entry **state, struct ipv6_nat_entry *tmp, enum nat_dir dir, __u32 off, const struct ipv6_nat_target *target)\n",
    "{\n",
    "    int ret;\n",
    "    *state = snat_v6_lookup (tuple);\n",
    "    ret = snat_v6_track_local (ctx, tuple, * state, dir, off, target);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    else if (*state)\n",
    "        return NAT_CONTINUE_XLATE;\n",
    "    else if (dir == NAT_DIR_INGRESS)\n",
    "        return tuple->nexthdr != IPPROTO_ICMPV6 && bpf_ntohs (tuple->dport) < target->min_port ? NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;\n",
    "    else\n",
    "        return snat_v6_new_mapping (ctx, tuple, (*state = tmp), target);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "snat_v6_lookup",
    "snat_v6_new_mapping",
    "snat_v6_track_local"
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
static __always_inline int snat_v6_handle_mapping(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry **state,
						  struct ipv6_nat_entry *tmp,
						  enum nat_dir dir, __u32 off,
						  const struct ipv6_nat_target *target)
{
	int ret;

	*state = snat_v6_lookup(tuple);
	ret = snat_v6_track_local(ctx, tuple, *state, dir, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else if (dir == NAT_DIR_INGRESS)
		return tuple->nexthdr != IPPROTO_ICMPV6 &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
	else
		return snat_v6_new_mapping(ctx, tuple, (*state = tmp), target);
}

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
  "startLine": 810,
  "endLine": 855,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_rewrite_egress",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6_ct_tuple *tuple",
    " struct ipv6_nat_entry *state",
    " __u32 off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "lwt_in",
    "sched_act",
    "lwt_out",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline int snat_v6_rewrite_egress (struct  __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, struct ipv6_nat_entry *state, __u32 off)\n",
    "{\n",
    "    struct csum_offset csum = {}\n",
    "    ;\n",
    "    __be32 sum;\n",
    "    int ret;\n",
    "    if (!ipv6_addrcmp (&state->to_saddr, &tuple->saddr) && state->to_sport == tuple->sport)\n",
    "        return 0;\n",
    "    sum = csum_diff (& tuple -> saddr, 16, & state -> to_saddr, 16, 0);\n",
    "    csum_l4_offset_and_flags (tuple->nexthdr, &csum);\n",
    "    if (state->to_sport != tuple->sport) {\n",
    "        switch (tuple->nexthdr) {\n",
    "        case IPPROTO_TCP :\n",
    "        case IPPROTO_UDP :\n",
    "            ret = l4_modify_port (ctx, off, offsetof (struct tcphdr, source), &csum, state->to_sport, tuple->sport);\n",
    "            if (ret < 0)\n",
    "                return ret;\n",
    "            break;\n",
    "        case IPPROTO_ICMPV6 :\n",
    "            {\n",
    "                __be32 from, to;\n",
    "                if (ctx_store_bytes (ctx, off + offsetof (struct icmp6hdr, icmp6_dataun.u_echo.identifier), &state->to_sport, sizeof (state->to_sport), 0) < 0)\n",
    "                    return DROP_WRITE_ERROR;\n",
    "                from = tuple->sport;\n",
    "                to = state->to_sport;\n",
    "                sum = csum_diff (& from, 4, & to, 4, sum);\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct ipv6hdr, saddr), &state->to_saddr, 16, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (csum.offset && csum_l4_replace (ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "csum_l4_replace",
    "offsetof",
    "csum_l4_offset_and_flags",
    "ipv6_addrcmp",
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
static __always_inline int snat_v6_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_saddr, &tuple->saddr) &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 16, &state->to_saddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off, offsetof(struct tcphdr, source),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &state->to_saddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

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
  "startLine": 857,
  "endLine": 904,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_rewrite_ingress",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct ipv6_ct_tuple *tuple",
    " struct ipv6_nat_entry *state",
    " __u32 off"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "lwt_in",
    "sched_act",
    "lwt_out",
    "lwt_seg6local"
  ],
  "source": [
    "static __always_inline int snat_v6_rewrite_ingress (struct  __ctx_buff *ctx, struct ipv6_ct_tuple *tuple, struct ipv6_nat_entry *state, __u32 off)\n",
    "{\n",
    "    struct csum_offset csum = {}\n",
    "    ;\n",
    "    __be32 sum;\n",
    "    int ret;\n",
    "    if (!ipv6_addrcmp (&state->to_daddr, &tuple->daddr) && state->to_dport == tuple->dport)\n",
    "        return 0;\n",
    "    sum = csum_diff (& tuple -> daddr, 16, & state -> to_daddr, 16, 0);\n",
    "    csum_l4_offset_and_flags (tuple->nexthdr, &csum);\n",
    "    if (state->to_dport != tuple->dport) {\n",
    "        switch (tuple->nexthdr) {\n",
    "        case IPPROTO_TCP :\n",
    "        case IPPROTO_UDP :\n",
    "            ret = l4_modify_port (ctx, off, offsetof (struct tcphdr, dest), &csum, state->to_dport, tuple->dport);\n",
    "            if (ret < 0)\n",
    "                return ret;\n",
    "            break;\n",
    "        case IPPROTO_ICMPV6 :\n",
    "            {\n",
    "                __be32 from, to;\n",
    "                if (ctx_store_bytes (ctx, off + offsetof (struct icmp6hdr, icmp6_dataun.u_echo.identifier), &state->to_dport, sizeof (state->to_dport), 0) < 0)\n",
    "                    return DROP_WRITE_ERROR;\n",
    "                from = tuple->dport;\n",
    "                to = state->to_dport;\n",
    "                sum = csum_diff (& from, 4, & to, 4, sum);\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct ipv6hdr, daddr), &state->to_daddr, 16, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (csum.offset && csum_l4_replace (ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)\n",
    "        return DROP_CSUM_L4;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "l4_modify_port",
    "csum_l4_replace",
    "offsetof",
    "csum_l4_offset_and_flags",
    "ipv6_addrcmp",
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
static __always_inline int snat_v6_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv6_ct_tuple *tuple,
						   struct ipv6_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 16, &state->to_daddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_dport,
					    sizeof(state->to_dport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->dport;
			to = state->to_dport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &state->to_daddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 906,
  "endLine": 920,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_can_skip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6_nat_target *target",
    " const struct ipv6_ct_tuple *tuple",
    " enum nat_dir dir",
    " bool icmp_echoreply"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool snat_v6_can_skip (const struct ipv6_nat_target *target, const struct ipv6_ct_tuple *tuple, enum nat_dir dir, bool icmp_echoreply)\n",
    "{\n",
    "    __u16 dport = bpf_ntohs (tuple->dport), sport = bpf_ntohs (tuple->sport);\n",
    "    if (dir == NAT_DIR_EGRESS && ((!target->src_from_world && sport < NAT_MIN_EGRESS) || icmp_echoreply))\n",
    "        return true;\n",
    "    if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))\n",
    "        return true;\n",
    "    return false;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs"
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
static __always_inline bool
snat_v6_can_skip(const struct ipv6_nat_target *target,
		 const struct ipv6_ct_tuple *tuple, enum nat_dir dir,
		 bool icmp_echoreply)
{
	__u16 dport = bpf_ntohs(tuple->dport), sport = bpf_ntohs(tuple->sport);

	if (dir == NAT_DIR_EGRESS &&
	    ((!target->src_from_world && sport < NAT_MIN_EGRESS) ||
	     icmp_echoreply))
		return true;
	if (dir == NAT_DIR_INGRESS && (dport < target->min_port || dport > target->max_port))
		return true;
	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    },
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
  "startLine": 922,
  "endLine": 977,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_create_dsr",
  "developer_inline_comments": [],
  "updateMaps": [
    "  SNAT_MAPPING_IPV6"
  ],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *to_saddr",
    " __be16 to_sport"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "map_update_elem",
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v6_create_dsr (struct  __ctx_buff *ctx, const union v6addr *to_saddr, __be16 to_sport)\n",
    "{\n",
    "    void *data, *data_end;\n",
    "    struct ipv6_ct_tuple tuple = {}\n",
    "    ;\n",
    "    struct ipv6_nat_entry state = {}\n",
    "    ;\n",
    "    struct ipv6hdr *ip6;\n",
    "    struct {\n",
    "        __be16 sport;\n",
    "        __be16 dport;\n",
    "    } l4hdr;\n",
    "\n",
    "    int ret, hdrlen;\n",
    "    __u32 off;\n",
    "    build_bug_on (sizeof (struct ipv6_nat_entry) > 64);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    tuple.nexthdr = ip6->nexthdr;\n",
    "    hdrlen = ipv6_hdrlen (ctx, & tuple.nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    ipv6_addr_copy (&tuple.daddr, (union v6addr *) &ip6->saddr);\n",
    "    ipv6_addr_copy (&tuple.saddr, (union v6addr *) &ip6->daddr);\n",
    "    tuple.flags = NAT_DIR_EGRESS;\n",
    "    off = ((void *) ip6 - data) + hdrlen;\n",
    "    switch (tuple.nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "        if (ctx_load_bytes (ctx, off, &l4hdr, sizeof (l4hdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        tuple.dport = l4hdr.sport;\n",
    "        tuple.sport = l4hdr.dport;\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_NAT_UNSUPP_PROTO;\n",
    "    }\n",
    "    state.common.created = bpf_mono_now ();\n",
    "    ipv6_addr_copy (&state.to_saddr, to_saddr);\n",
    "    state.to_sport = to_sport;\n",
    "    ret = map_update_elem (& SNAT_MAPPING_IPV6, & tuple, & state, 0);\n",
    "    if (ret)\n",
    "        return ret;\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "bpf_mono_now",
    "build_bug_on",
    "ipv6_hdrlen",
    "ipv6_addr_copy",
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
static __always_inline __maybe_unused int snat_v6_create_dsr(struct __ctx_buff *ctx,
							     const union v6addr *to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv6_ct_tuple tuple = {};
	struct ipv6_nat_entry state = {};
	struct ipv6hdr *ip6;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	int ret, hdrlen;
	__u32 off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->daddr);
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip6 - data) + hdrlen;

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	ipv6_addr_copy(&state.to_saddr, to_saddr);
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
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
  "startLine": 979,
  "endLine": 1054,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " enum nat_dir dir",
    " const struct ipv6_nat_target *target"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v6_process (struct  __ctx_buff *ctx, enum nat_dir dir, const struct ipv6_nat_target *target)\n",
    "{\n",
    "    struct icmp6hdr icmp6hdr __align_stack_8;\n",
    "    struct ipv6_nat_entry *state, tmp;\n",
    "    struct ipv6_ct_tuple tuple = {}\n",
    "    ;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int ret, hdrlen;\n",
    "    struct {\n",
    "        __be16 sport;\n",
    "        __be16 dport;\n",
    "    } l4hdr;\n",
    "\n",
    "    __u8 nexthdr;\n",
    "    __u32 off;\n",
    "    bool icmp_echoreply = false;\n",
    "    build_bug_on (sizeof (struct ipv6_nat_entry) > 64);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    nexthdr = ip6->nexthdr;\n",
    "    hdrlen = ipv6_hdrlen (ctx, & nexthdr);\n",
    "    if (hdrlen < 0)\n",
    "        return hdrlen;\n",
    "    tuple.nexthdr = nexthdr;\n",
    "    ipv6_addr_copy (&tuple.daddr, (union v6addr *) &ip6->daddr);\n",
    "    ipv6_addr_copy (&tuple.saddr, (union v6addr *) &ip6->saddr);\n",
    "    tuple.flags = dir;\n",
    "    off = ((void *) ip6 - data) + hdrlen;\n",
    "    switch (tuple.nexthdr) {\n",
    "    case IPPROTO_TCP :\n",
    "    case IPPROTO_UDP :\n",
    "        if (ctx_load_bytes (ctx, off, &l4hdr, sizeof (l4hdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        tuple.dport = l4hdr.dport;\n",
    "        tuple.sport = l4hdr.sport;\n",
    "        break;\n",
    "    case IPPROTO_ICMPV6 :\n",
    "        if (ctx_load_bytes (ctx, off, &icmp6hdr, sizeof (icmp6hdr)) < 0)\n",
    "            return DROP_INVALID;\n",
    "        if (icmp6hdr.icmp6_type == ICMP6_NS_MSG_TYPE || icmp6hdr.icmp6_type == ICMP6_NA_MSG_TYPE)\n",
    "            return CTX_ACT_OK;\n",
    "        if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST && icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)\n",
    "            return DROP_NAT_UNSUPP_PROTO;\n",
    "        if (icmp6hdr.icmp6_type == ICMPV6_ECHO_REQUEST) {\n",
    "            tuple.dport = 0;\n",
    "            tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;\n",
    "        }\n",
    "        else {\n",
    "            tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;\n",
    "            tuple.sport = 0;\n",
    "            icmp_echoreply = true;\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        return NAT_PUNT_TO_STACK;\n",
    "    }\n",
    "    if (snat_v6_can_skip (target, &tuple, dir, icmp_echoreply))\n",
    "        return NAT_PUNT_TO_STACK;\n",
    "    ret = snat_v6_handle_mapping (ctx, & tuple, & state, & tmp, dir, off, target);\n",
    "    if (ret > 0)\n",
    "        return CTX_ACT_OK;\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    return dir == NAT_DIR_EGRESS ? snat_v6_rewrite_egress (ctx, &tuple, state, off) : snat_v6_rewrite_ingress (ctx, &tuple, state, off);\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "snat_v6_rewrite_egress",
    "snat_v6_can_skip",
    "snat_v6_rewrite_ingress",
    "build_bug_on",
    "ipv6_hdrlen",
    "snat_v6_handle_mapping",
    "ipv6_addr_copy",
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
static __always_inline __maybe_unused int
snat_v6_process(struct __ctx_buff *ctx, enum nat_dir dir,
		const struct ipv6_nat_target *target)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state, tmp;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u8 nexthdr;
	__u32 off;
	bool icmp_echoreply = false;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	tuple.nexthdr = nexthdr;
	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->saddr);
	tuple.flags = dir;
	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		/* Letting neighbor solicitation / advertisement pass through. */
		if (icmp6hdr.icmp6_type == ICMP6_NS_MSG_TYPE ||
			icmp6hdr.icmp6_type == ICMP6_NA_MSG_TYPE)
			return CTX_ACT_OK;
		if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
		    icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmp6hdr.icmp6_type == ICMPV6_ECHO_REQUEST) {
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
		} else {
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_can_skip(target, &tuple, dir, icmp_echoreply))
		return NAT_PUNT_TO_STACK;
	ret = snat_v6_handle_mapping(ctx, &tuple, &state, &tmp, dir, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return dir == NAT_DIR_EGRESS ?
	       snat_v6_rewrite_egress(ctx, &tuple, state, off) :
	       snat_v6_rewrite_ingress(ctx, &tuple, state, off);
}
#else
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
  "startLine": 1056,
  "endLine": 1062,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " enum nat_dir dir __maybe_unused",
    " const struct ipv6_nat_target * target __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static __always_inline __maybe_unused int snat_v6_process (struct  __ctx_buff * ctx __maybe_unused, enum nat_dir dir __maybe_unused, const struct ipv6_nat_target * target __maybe_unused)\n",
    "{\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "snat_v6_rewrite_egress",
    "snat_v6_can_skip",
    "snat_v6_rewrite_ingress",
    "build_bug_on",
    "ipv6_hdrlen",
    "snat_v6_handle_mapping",
    "ipv6_addr_copy",
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
static __always_inline __maybe_unused
int snat_v6_process(struct __ctx_buff *ctx __maybe_unused,
		    enum nat_dir dir __maybe_unused,
		    const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1064,
  "endLine": 1067,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_delete_tuples",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6_ct_tuple * tuple __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void snat_v6_delete_tuples (struct ipv6_ct_tuple * tuple __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "snat_v6_ct_canonicalize",
    "snat_v6_reverse_tuple",
    "snat_v6_delete"
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
static __always_inline __maybe_unused
void snat_v6_delete_tuples(struct ipv6_ct_tuple *tuple __maybe_unused)
{
}
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1070,
  "endLine": 1088,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "snat_v6_has_v4_match",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv4_ct_tuple * tuple4 __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool snat_v6_has_v4_match (const struct ipv4_ct_tuple * tuple4 __maybe_unused)\n",
    "{\n",
    "\n",
    "#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)\n",
    "    struct ipv6_ct_tuple tuple6;\n",
    "    memset (&tuple6, 0, sizeof (tuple6));\n",
    "    tuple6.nexthdr = tuple4->nexthdr;\n",
    "    build_v4_in_v6 (&tuple6.saddr, tuple4->saddr);\n",
    "    build_v4_in_v6 (&tuple6.daddr, tuple4->daddr);\n",
    "    tuple6.sport = tuple4->sport;\n",
    "    tuple6.dport = tuple4->dport;\n",
    "    tuple6.flags = NAT_DIR_INGRESS;\n",
    "    return snat_v6_lookup (&tuple6);\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "build_v4_in_v6",
    "snat_v6_lookup",
    "memset",
    "defined"
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
static __always_inline bool
snat_v6_has_v4_match(const struct ipv4_ct_tuple *tuple4 __maybe_unused)
{
#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	tuple6.nexthdr = tuple4->nexthdr;
	build_v4_in_v6(&tuple6.saddr, tuple4->saddr);
	build_v4_in_v6(&tuple6.daddr, tuple4->daddr);
	tuple6.sport = tuple4->sport;
	tuple6.dport = tuple4->dport;
	tuple6.flags = NAT_DIR_INGRESS;

	return snat_v6_lookup(&tuple6);
#else
	return false;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Delete entry with <[ key ]>(IP: 1) from map. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_delete_elem",
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1090,
  "endLine": 1100,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "ct_delete4",
  "developer_inline_comments": [],
  "updateMaps": [
    "",
    " map"
  ],
  "readMaps": [],
  "input": [
    "const void *map",
    " struct ipv4_ct_tuple *tuple",
    " struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "map_delete_elem"
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
    "static __always_inline __maybe_unused void ct_delete4 (const void *map, struct ipv4_ct_tuple *tuple, struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int err;\n",
    "    err = map_delete_elem (map, tuple);\n",
    "    if (err < 0)\n",
    "        cilium_dbg (ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);\n",
    "    else\n",
    "        snat_v4_delete_tuples (tuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg",
    "snat_v4_delete_tuples"
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
static __always_inline __maybe_unused void
ct_delete4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v4_delete_tuples(tuple);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Delete entry with <[ key ]>(IP: 1) from map. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_delete_elem",
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1102,
  "endLine": 1112,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/nat.h",
  "funcName": "ct_delete6",
  "developer_inline_comments": [],
  "updateMaps": [
    "",
    " map"
  ],
  "readMaps": [],
  "input": [
    "const void *map",
    " struct ipv6_ct_tuple *tuple",
    " struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "map_delete_elem"
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
    "static __always_inline __maybe_unused void ct_delete6 (const void *map, struct ipv6_ct_tuple *tuple, struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int err;\n",
    "    err = map_delete_elem (map, tuple);\n",
    "    if (err < 0)\n",
    "        cilium_dbg (ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);\n",
    "    else\n",
    "        snat_v6_delete_tuples (tuple);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg",
    "snat_v6_delete_tuples"
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
static __always_inline __maybe_unused void
ct_delete6(const void *map, struct ipv6_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v6_delete_tuples(tuple);
}

#endif /* __LIB_NAT__ */
