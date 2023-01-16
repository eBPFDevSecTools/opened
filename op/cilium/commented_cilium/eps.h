/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EPS_H_
#define __LIB_EPS_H_

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "maps.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn &ENDPOINTS_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 12,
  "endLine": 21,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*__lookup_ip6_endpoint",
  "updateMaps": [],
  "readMaps": [
    " ENDPOINTS_MAP"
  ],
  "input": [
    "const union v6addr *ip6"
  ],
  "output": "static__always_inline__maybe_unusedstructendpoint_info",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "cgroup_device",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_sysctl",
    "lwt_out",
    "cgroup_sock_addr"
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
static __always_inline __maybe_unused struct endpoint_info *
__lookup_ip6_endpoint(const union v6addr *ip6)
{
	struct endpoint_key key = {};

	key.ip6 = *ip6;
	key.family = ENDPOINT_KEY_IPV6;

	return map_lookup_elem(&ENDPOINTS_MAP, &key);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 23,
  "endLine": 27,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*lookup_ip6_endpoint",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6hdr *ip6"
  ],
  "output": "static__always_inline__maybe_unusedstructendpoint_info",
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
static __always_inline __maybe_unused struct endpoint_info *
lookup_ip6_endpoint(const struct ipv6hdr *ip6)
{
	return __lookup_ip6_endpoint((union v6addr *)&ip6->daddr);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn &ENDPOINTS_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 29,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*__lookup_ip4_endpoint",
  "updateMaps": [],
  "readMaps": [
    " ENDPOINTS_MAP"
  ],
  "input": [
    "__u32 ip"
  ],
  "output": "static__always_inline__maybe_unusedstructendpoint_info",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "cgroup_device",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_sysctl",
    "lwt_out",
    "cgroup_sock_addr"
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
static __always_inline __maybe_unused struct endpoint_info *
__lookup_ip4_endpoint(__u32 ip)
{
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&ENDPOINTS_MAP, &key);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 40,
  "endLine": 44,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*lookup_ip4_endpoint",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr *ip4"
  ],
  "output": "static__always_inline__maybe_unusedstructendpoint_info",
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
static __always_inline __maybe_unused struct endpoint_info *
lookup_ip4_endpoint(const struct iphdr *ip4)
{
	return __lookup_ip4_endpoint(ip4->daddr);
}

#ifdef SOCKMAP
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn &EP_POLICY_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 47,
  "endLine": 56,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*lookup_ip4_endpoint_policy_map",
  "updateMaps": [],
  "readMaps": [
    " EP_POLICY_MAP"
  ],
  "input": [
    "__u32 ip"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "cgroup_device",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_sysctl",
    "lwt_out",
    "cgroup_sock_addr"
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
static __always_inline void *
lookup_ip4_endpoint_policy_map(__u32 ip)
{
	struct endpoint_key key = {};

	key.ip4 = ip;
	key.family = ENDPOINT_KEY_IPV4;

	return map_lookup_elem(&EP_POLICY_MAP, &key);
}
#endif

/* IPCACHE_STATIC_PREFIX gets sizeof non-IP, non-prefix part of ipcache_key */
#define IPCACHE_STATIC_PREFIX							\
	(8 * (sizeof(struct ipcache_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))
#define IPCACHE_PREFIX_LEN(PREFIX) (IPCACHE_STATIC_PREFIX + (PREFIX))

#define V6_CACHE_KEY_LEN (sizeof(union v6addr)*8)

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn map",
          " &key"
        ]
      }
    ]
  },
  "startLine": 67,
  "endLine": 78,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*ipcache_lookup6",
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "const void *map",
    " const union v6addr *addr",
    " __u32 prefix"
  ],
  "output": "static__always_inline__maybe_unusedstructremote_endpoint_info",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "cgroup_device",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_sysctl",
    "lwt_out",
    "cgroup_sock_addr"
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
static __always_inline __maybe_unused struct remote_endpoint_info *
ipcache_lookup6(const void *map, const union v6addr *addr,
		__u32 prefix)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV6,
		.ip6 = *addr,
	};
	ipv6_addr_clear_suffix(&key.ip6, prefix);
	return map_lookup_elem(map, &key);
}

#define V4_CACHE_KEY_LEN (sizeof(__u32)*8)

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn map",
          " &key"
        ]
      }
    ]
  },
  "startLine": 82,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/eps.h",
  "funcName": "*ipcache_lookup4",
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "const void *map",
    " __be32 addr",
    " __u32 prefix"
  ],
  "output": "static__always_inline__maybe_unusedstructremote_endpoint_info",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_seg6local",
    "sched_cls",
    "tracepoint",
    "sk_msg",
    "perf_event",
    "cgroup_device",
    "kprobe",
    "sock_ops",
    "sk_skb",
    "lwt_in",
    "xdp",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_sysctl",
    "lwt_out",
    "cgroup_sock_addr"
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
static __always_inline __maybe_unused struct remote_endpoint_info *
ipcache_lookup4(const void *map, __be32 addr, __u32 prefix)
{
	struct ipcache_key key = {
		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};
	key.ip4 &= GET_PREFIX(prefix);
	return map_lookup_elem(map, &key);
}

#ifndef HAVE_LPM_TRIE_MAP_TYPE
/* Define a function with the following NAME which iterates through PREFIXES
 * (a list of integers ordered from high to low representing prefix length),
 * performing a lookup in MAP using LOOKUP_FN to find a provided IP of type
 * IPTYPE.
 */
#define LPM_LOOKUP_FN(NAME, IPTYPE, PREFIXES, MAP, LOOKUP_FN)		\
static __always_inline __maybe_unused struct remote_endpoint_info *	\
NAME(IPTYPE addr)							\
{									\
	int prefixes[] = { PREFIXES };					\
	const int size = ARRAY_SIZE(prefixes);				\
	struct remote_endpoint_info *info;				\
	int i;								\
									\
_Pragma("unroll")							\
	for (i = 0; i < size; i++) {					\
		info = LOOKUP_FN(&MAP, addr, prefixes[i]);		\
		if (info != NULL)					\
			return info;					\
	}								\
									\
	return NULL;							\
}
#ifdef IPCACHE6_PREFIXES
LPM_LOOKUP_FN(lookup_ip6_remote_endpoint, const union v6addr *,
	      IPCACHE6_PREFIXES, IPCACHE_MAP, ipcache_lookup6)
#endif
#ifdef IPCACHE4_PREFIXES
LPM_LOOKUP_FN(lookup_ip4_remote_endpoint, __be32, IPCACHE4_PREFIXES,
	      IPCACHE_MAP, ipcache_lookup4)
#endif
#undef LPM_LOOKUP_FN
#else /* HAVE_LPM_TRIE_MAP_TYPE */
#define lookup_ip6_remote_endpoint(addr) \
	ipcache_lookup6(&IPCACHE_MAP, addr, V6_CACHE_KEY_LEN)
#define lookup_ip4_remote_endpoint(addr) \
	ipcache_lookup4(&IPCACHE_MAP, addr, V4_CACHE_KEY_LEN)
#endif /* HAVE_LPM_TRIE_MAP_TYPE */
#endif /* __LIB_EPS_H_ */
