/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY

/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

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
  "startLine": 20,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "lookup_ip4_egress_gw_policy",
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
      "start_line": 13,
      "end_line": 15,
      "text": "/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of\n * an egress policy key (i.e. the source IP).\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " EGRESS_POLICY_MAP"
  ],
  "input": [
    "__be32 saddr",
    " __be32 daddr"
  ],
  "output": "static__always_inlinestructegress_gw_policy_entry",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy (__be32 saddr, __be32 daddr)\n",
    "{\n",
    "    struct egress_gw_policy_key key = {\n",
    "        .lpm_key = {EGRESS_IPV4_PREFIX,\n",
    "            {}},\n",
    "        .saddr = saddr,\n",
    "        .daddr = daddr,}\n",
    "    ;\n",
    "    return map_lookup_elem (&EGRESS_POLICY_MAP, &key);\n",
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
struct egress_gw_policy_entry *lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

#endif /* ENABLE_EGRESS_GATEWAY */

#ifdef ENABLE_SRV6
# ifdef ENABLE_IPV4

/* SRV6_VRF_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key4.
 */
#  define SRV6_VRF_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_vrf_key4) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX4_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_VRF_IPV4_PREFIX SRV6_VRF_PREFIX4_LEN(32)
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
  "startLine": 44,
  "endLine": 53,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_vrf4",
  "developer_inline_comments": [
    {
      "start_line": 31,
      "end_line": 31,
      "text": "/* ENABLE_EGRESS_GATEWAY */"
    },
    {
      "start_line": 36,
      "end_line": 38,
      "text": "/* SRV6_VRF_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of\n * srv6_vrf_key4.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " SRV6_VRF_MAP4"
  ],
  "input": [
    "__be32 sip",
    " __be32 dip"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u32 *srv6_lookup_vrf4 (__be32 sip, __be32 dip)\n",
    "{\n",
    "    struct srv6_vrf_key4 key = {\n",
    "        .lpm = {SRV6_VRF_IPV4_PREFIX,\n",
    "            {}},\n",
    "        .src_ip = sip,\n",
    "        .dst_cidr = dip,}\n",
    "    ;\n",
    "    return map_lookup_elem (&SRV6_VRF_MAP4, &key);\n",
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
static __always_inline __u32*
srv6_lookup_vrf4(__be32 sip, __be32 dip)
{
	struct srv6_vrf_key4 key = {
		.lpm = { SRV6_VRF_IPV4_PREFIX, {} },
		.src_ip = sip,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP4, &key);
}

/* SRV6_POLICY_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key4.
 */
#  define SRV6_POLICY_STATIC_PREFIX4						\
	(8 * (sizeof(struct srv6_policy_key4) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
#  define SRV6_POLICY_PREFIX4_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX4 + (PREFIX))
#  define SRV6_POLICY_IPV4_PREFIX SRV6_POLICY_PREFIX4_LEN(32)
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
  "startLine": 63,
  "endLine": 72,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_policy4",
  "developer_inline_comments": [
    {
      "start_line": 55,
      "end_line": 57,
      "text": "/* SRV6_POLICY_STATIC_PREFIX4 gets sizeof non-IP, non-prefix part of\n * srv6_policy_key4.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " SRV6_POLICY_MAP4"
  ],
  "input": [
    "__u32 vrf_id",
    " __be32 dip"
  ],
  "output": "static__always_inlineunionv6addr",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline union v6addr *srv6_lookup_policy4 (__u32 vrf_id, __be32 dip)\n",
    "{\n",
    "    struct srv6_policy_key4 key = {\n",
    "        .lpm = {SRV6_POLICY_IPV4_PREFIX,\n",
    "            {}},\n",
    "        .vrf_id = vrf_id,\n",
    "        .dst_cidr = dip,}\n",
    "    ;\n",
    "    return map_lookup_elem (&SRV6_POLICY_MAP4, &key);\n",
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
static __always_inline union v6addr *
srv6_lookup_policy4(__u32 vrf_id, __be32 dip)
{
	struct srv6_policy_key4 key = {
		.lpm = { SRV6_POLICY_IPV4_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP4, &key);
}
# endif /* ENABLE_IPV4 */

/* SRV6_VRF_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_vrf_key6.
 */
#  define SRV6_VRF_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_vrf_key6) - sizeof(struct bpf_lpm_trie_key)\
	      - 4))
#  define SRV6_VRF_PREFIX6_LEN(PREFIX) (SRV6_VRF_STATIC_PREFIX6 + (PREFIX))
#  define SRV6_VRF_IPV6_PREFIX SRV6_VRF_PREFIX6_LEN(32)
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
  "startLine": 83,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_vrf6",
  "developer_inline_comments": [
    {
      "start_line": 75,
      "end_line": 77,
      "text": "/* SRV6_VRF_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of\n * srv6_vrf_key6.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " SRV6_VRF_MAP6"
  ],
  "input": [
    "const struct in6_addr *sip",
    " const struct in6_addr *dip"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u32 *srv6_lookup_vrf6 (const struct in6_addr *sip, const struct in6_addr *dip)\n",
    "{\n",
    "    struct srv6_vrf_key6 key = {\n",
    "        .lpm = {SRV6_VRF_IPV6_PREFIX,\n",
    "            {}},\n",
    "        .src_ip = *(unionv6addr*) sip,\n",
    "        .dst_cidr = *(unionv6addr*) dip,}\n",
    "    ;\n",
    "    return map_lookup_elem (&SRV6_VRF_MAP6, &key);\n",
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
static __always_inline __u32*
srv6_lookup_vrf6(const struct in6_addr *sip, const struct in6_addr *dip)
{
	struct srv6_vrf_key6 key = {
		.lpm = { SRV6_VRF_IPV6_PREFIX, {} },
		.src_ip = *(union v6addr *)sip,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_VRF_MAP6, &key);
}

/* SRV6_POLICY_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of
 * srv6_policy_key6.
 */
# define SRV6_POLICY_STATIC_PREFIX6						\
	(8 * (sizeof(struct srv6_policy_key6) - sizeof(struct bpf_lpm_trie_key)	\
	      - 4))
# define SRV6_POLICY_PREFIX6_LEN(PREFIX) (SRV6_POLICY_STATIC_PREFIX6 + (PREFIX))
# define SRV6_POLICY_IPV6_PREFIX SRV6_POLICY_PREFIX6_LEN(128)

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
  "startLine": 103,
  "endLine": 112,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_policy6",
  "developer_inline_comments": [
    {
      "start_line": 94,
      "end_line": 96,
      "text": "/* SRV6_POLICY_STATIC_PREFIX6 gets sizeof non-IP, non-prefix part of\n * srv6_policy_key6.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " SRV6_POLICY_MAP6"
  ],
  "input": [
    "__u32 vrf_id",
    " const struct in6_addr *dip"
  ],
  "output": "static__always_inlineunionv6addr",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline union v6addr *srv6_lookup_policy6 (__u32 vrf_id, const struct in6_addr *dip)\n",
    "{\n",
    "    struct srv6_policy_key6 key = {\n",
    "        .lpm = {SRV6_POLICY_IPV6_PREFIX,\n",
    "            {}},\n",
    "        .vrf_id = vrf_id,\n",
    "        .dst_cidr = *(unionv6addr*) dip,}\n",
    "    ;\n",
    "    return map_lookup_elem (&SRV6_POLICY_MAP6, &key);\n",
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
static __always_inline union v6addr *
srv6_lookup_policy6(__u32 vrf_id, const struct in6_addr *dip)
{
	struct srv6_policy_key6 key = {
		.lpm = { SRV6_POLICY_IPV6_PREFIX, {} },
		.vrf_id = vrf_id,
		.dst_cidr = *(union v6addr *)dip,
	};
	return map_lookup_elem(&SRV6_POLICY_MAP6, &key);
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
  "startLine": 114,
  "endLine": 123,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_sid",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  SRV6_SID_MAP"
  ],
  "input": [
    "const struct in6_addr *sid"
  ],
  "output": "static__always_inline__u32",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline __u32 srv6_lookup_sid (const struct in6_addr *sid)\n",
    "{\n",
    "    __u32 *vrf_id;\n",
    "    vrf_id = map_lookup_elem (& SRV6_SID_MAP, sid);\n",
    "    if (vrf_id)\n",
    "        return *vrf_id;\n",
    "    return 0;\n",
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
static __always_inline __u32
srv6_lookup_sid(const struct in6_addr *sid)
{
	__u32 *vrf_id;

	vrf_id = map_lookup_elem(&SRV6_SID_MAP, sid);
	if (vrf_id)
		return *vrf_id;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 125,
  "endLine": 134,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "is_srv6_packet",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct ipv6hdr *ip6"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool is_srv6_packet (const struct ipv6hdr *ip6)\n",
    "{\n",
    "\n",
    "#ifndef ENABLE_SRV6_REDUCED_ENCAP\n",
    "    if (ip6->nexthdr == NEXTHDR_ROUTING)\n",
    "        return true;\n",
    "\n",
    "#endif\n",
    "    return ip6->nexthdr == IPPROTO_IPIP || ip6->nexthdr == IPPROTO_IPV6;\n",
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
is_srv6_packet(const struct ipv6hdr *ip6)
{
#ifndef ENABLE_SRV6_REDUCED_ENCAP
	if (ip6->nexthdr == NEXTHDR_ROUTING)
		return true;
#endif
	return ip6->nexthdr == IPPROTO_IPIP ||
	       ip6->nexthdr == IPPROTO_IPV6;
}

# ifndef SKIP_SRV6_HANDLING
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 137,
  "endLine": 144,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "ctx_adjust_hroom_flags",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inline__u64",
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
    "static __always_inline __u64 ctx_adjust_hroom_flags (void)\n",
    "{\n",
    "\n",
    "#ifdef BPF_HAVE_CSUM_LEVEL\n",
    "    return BPF_F_ADJ_ROOM_NO_CSUM_RESET;\n",
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
static __always_inline __u64 ctx_adjust_hroom_flags(void)
{
#ifdef BPF_HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#else
	return 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 146,
  "endLine": 171,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_encapsulation",
  "developer_inline_comments": [
    {
      "start_line": 158,
      "end_line": 158,
      "text": "/* Add room between Ethernet and network headers. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int growth",
    " __u16 new_payload_len",
    " __u8 nexthdr",
    " union v6addr *saddr",
    " struct in6_addr *sid"
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
    "static __always_inline int srv6_encapsulation (struct  __ctx_buff *ctx, int growth, __u16 new_payload_len, __u8 nexthdr, union v6addr *saddr, struct in6_addr *sid)\n",
    "{\n",
    "    __u32 len = sizeof (struct ipv6hdr) - 2 * sizeof (struct in6_addr);\n",
    "    struct ipv6hdr new_ip6 = {\n",
    "        .version = 0x6,\n",
    "        .payload_len = bpf_htons (new_payload_len),\n",
    "        .nexthdr = nexthdr,\n",
    "        .hop_limit = IPDEFTTL,}\n",
    "    ;\n",
    "    if (ctx_adjust_hroom (ctx, growth, BPF_ADJ_ROOM_MAC, ctx_adjust_hroom_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN, &new_ip6, len, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct ipv6hdr, saddr), saddr, sizeof (union v6addr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, ETH_HLEN + offsetof (struct ipv6hdr, daddr), sid, sizeof (struct in6_addr), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_adjust_hroom_flags",
    "ctx_store_bytes",
    "ctx_adjust_hroom",
    "offsetof",
    "bpf_htons"
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
srv6_encapsulation(struct __ctx_buff *ctx, int growth, __u16 new_payload_len,
		   __u8 nexthdr, union v6addr *saddr, struct in6_addr *sid)
{
	__u32 len = sizeof(struct ipv6hdr) - 2 * sizeof(struct in6_addr);
	struct ipv6hdr new_ip6 = {
		.version     = 0x6,
		.payload_len = bpf_htons(new_payload_len),
		.nexthdr     = nexthdr,
		.hop_limit   = IPDEFTTL,
	};

	/* Add room between Ethernet and network headers. */
	if (ctx_adjust_hroom(ctx, growth, BPF_ADJ_ROOM_MAC,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN, &new_ip6, len, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    saddr, sizeof(union v6addr), 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    sid, sizeof(struct in6_addr), 0) < 0)
		return DROP_WRITE_ERROR;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 210,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_decapsulation",
  "developer_inline_comments": [
    {
      "start_line": 191,
      "end_line": 195,
      "text": "/* ctx_change_proto above shrinks the packet from IPv6 header\n\t\t * length to IPv4 header length. It removes that space from the\n\t\t * same header we will later delete.\n\t\t * Thus, deduce this space from the next packet shrinking.\n\t\t */"
    },
    {
      "start_line": 205,
      "end_line": 205,
      "text": "/* Remove the outer IPv6 header. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
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
    "static __always_inline int srv6_decapsulation (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u16 new_proto = bpf_htons (ETH_P_IP);\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int shrink;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    switch (ip6->nexthdr) {\n",
    "    case IPPROTO_IPIP :\n",
    "        if (ctx_change_proto (ctx, new_proto, 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        if (ctx_store_bytes (ctx, offsetof (struct ethhdr, h_proto), &new_proto, sizeof (new_proto), 0) < 0)\n",
    "            return DROP_WRITE_ERROR;\n",
    "        shrink = sizeof (struct iphdr);\n",
    "        break;\n",
    "    case IPPROTO_IPV6 :\n",
    "        shrink = sizeof (struct ipv6hdr);\n",
    "        break;\n",
    "    default :\n",
    "        return DROP_INVALID;\n",
    "    }\n",
    "    if (ctx_adjust_hroom (ctx, -shrink, BPF_ADJ_ROOM_MAC, ctx_adjust_hroom_flags ()))\n",
    "        return DROP_INVALID;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "ctx_adjust_hroom_flags",
    "ctx_store_bytes",
    "ctx_adjust_hroom",
    "offsetof",
    "ctx_change_proto",
    "bpf_htons"
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
srv6_decapsulation(struct __ctx_buff *ctx)
{
	__u16 new_proto = bpf_htons(ETH_P_IP);
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int shrink;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	switch (ip6->nexthdr) {
	case IPPROTO_IPIP:
		if (ctx_change_proto(ctx, new_proto, 0) < 0)
			return DROP_WRITE_ERROR;
		if (ctx_store_bytes(ctx, offsetof(struct ethhdr, h_proto),
				    &new_proto, sizeof(new_proto), 0) < 0)
			return DROP_WRITE_ERROR;
		/* ctx_change_proto above shrinks the packet from IPv6 header
		 * length to IPv4 header length. It removes that space from the
		 * same header we will later delete.
		 * Thus, deduce this space from the next packet shrinking.
		 */
		shrink = sizeof(struct iphdr);
		break;
	case IPPROTO_IPV6:
		shrink = sizeof(struct ipv6hdr);
		break;
	default:
		return DROP_INVALID;
	}

	/* Remove the outer IPv6 header. */
	if (ctx_adjust_hroom(ctx, -shrink, BPF_ADJ_ROOM_MAC,
			     ctx_adjust_hroom_flags()))
		return DROP_INVALID;
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 212,
  "endLine": 252,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_create_state_entry",
  "developer_inline_comments": [
    {
      "start_line": 248,
      "end_line": 248,
      "text": "/* ENABLE_IPV4 */"
    }
  ],
  "updateMaps": [
    " SRV6_STATE_MAP6",
    " SRV6_STATE_MAP4"
  ],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
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
    "static __always_inline int srv6_create_state_entry (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct srv6_ipv6_2tuple *outer_ips;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    outer_ips = (struct srv6_ipv6_2tuple *) &ip6->saddr;\n",
    "    switch (ip6->nexthdr) {\n",
    "    case IPPROTO_IPV6 :\n",
    "        {\n",
    "            struct ipv6hdr *inner = ip6 + 1;\n",
    "            struct srv6_ipv6_2tuple *inner_ips;\n",
    "            if ((void *) inner + sizeof (*inner) > data_end)\n",
    "                return DROP_INVALID;\n",
    "            inner_ips = (struct srv6_ipv6_2tuple *) &inner->saddr;\n",
    "            if (map_update_elem (&SRV6_STATE_MAP6, inner_ips, outer_ips, 0) < 0)\n",
    "                return DROP_INVALID;\n",
    "        }\n",
    "\n",
    "#  ifdef ENABLE_IPV4\n",
    "    case IPPROTO_IPIP :\n",
    "        {\n",
    "            struct iphdr *inner = (struct iphdr *) (ip6 + 1);\n",
    "            struct srv6_ipv4_2tuple *inner_ips;\n",
    "            if ((void *) inner + sizeof (*inner) > data_end)\n",
    "                return DROP_INVALID;\n",
    "            inner_ips = (struct srv6_ipv4_2tuple *) &inner->saddr;\n",
    "            if (map_update_elem (&SRV6_STATE_MAP4, inner_ips, outer_ips, 0) < 0)\n",
    "                return DROP_INVALID;\n",
    "        }\n",
    "\n",
    "#  endif /* ENABLE_IPV4 */\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data"
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
srv6_create_state_entry(struct __ctx_buff *ctx)
{
	struct srv6_ipv6_2tuple *outer_ips;
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	outer_ips = (struct srv6_ipv6_2tuple *)&ip6->saddr;

	switch (ip6->nexthdr) {
	case IPPROTO_IPV6: {
		struct ipv6hdr *inner = ip6 + 1;
		struct srv6_ipv6_2tuple *inner_ips;

		if ((void *)inner + sizeof(*inner) > data_end)
			return DROP_INVALID;
		inner_ips = (struct srv6_ipv6_2tuple *)&inner->saddr;

		if (map_update_elem(&SRV6_STATE_MAP6, inner_ips, outer_ips, 0) < 0)
			return DROP_INVALID;
	}
#  ifdef ENABLE_IPV4
	case IPPROTO_IPIP: {
		struct iphdr *inner = (struct iphdr *)(ip6 + 1);
		struct srv6_ipv4_2tuple *inner_ips;

		if ((void *)inner + sizeof(*inner) > data_end)
			return DROP_INVALID;
		inner_ips = (struct srv6_ipv4_2tuple *)&inner->saddr;

		if (map_update_elem(&SRV6_STATE_MAP4, inner_ips, outer_ips, 0) < 0)
			return DROP_INVALID;
	}
#  endif /* ENABLE_IPV4 */
	}

	return 0;
}

#  ifdef ENABLE_IPV4
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
  "startLine": 255,
  "endLine": 260,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_state_entry4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " SRV6_STATE_MAP4"
  ],
  "input": [
    "struct iphdr *ip4"
  ],
  "output": "static__always_inlinestructsrv6_ipv6_2tuple",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct srv6_ipv6_2tuple *srv6_lookup_state_entry4 (struct iphdr *ip4)\n",
    "{\n",
    "    return map_lookup_elem (&SRV6_STATE_MAP4, (struct srv6_ipv4_2tuple *) &ip4->saddr);\n",
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
static __always_inline struct srv6_ipv6_2tuple *
srv6_lookup_state_entry4(struct iphdr *ip4)
{
	return map_lookup_elem(&SRV6_STATE_MAP4,
			       (struct srv6_ipv4_2tuple *)&ip4->saddr);
}
#  endif /* ENABLE_IPV4 */

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
  "startLine": 263,
  "endLine": 268,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_lookup_state_entry6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " SRV6_STATE_MAP6"
  ],
  "input": [
    "struct ipv6hdr *ip6"
  ],
  "output": "static__always_inlinestructsrv6_ipv6_2tuple",
  "helper": [
    "map_lookup_elem"
  ],
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
    "static __always_inline struct srv6_ipv6_2tuple *srv6_lookup_state_entry6 (struct ipv6hdr *ip6)\n",
    "{\n",
    "    return map_lookup_elem (&SRV6_STATE_MAP6, (struct srv6_ipv6_2tuple *) &ip6->saddr);\n",
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
static __always_inline struct srv6_ipv6_2tuple *
srv6_lookup_state_entry6(struct ipv6hdr *ip6)
{
	return map_lookup_elem(&SRV6_STATE_MAP6,
			       (struct srv6_ipv6_2tuple *)&ip6->saddr);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 270,
  "endLine": 310,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_handling4",
  "developer_inline_comments": [
    {
      "start_line": 280,
      "end_line": 280,
      "text": "/* Inner packet is IPv4. */"
    },
    {
      "start_line": 284,
      "end_line": 289,
      "text": "/* IPv4's tot_len fields has the size of the entire packet\n\t * including headers while IPv6's payload_len field has only\n\t * the size of the IPv6 payload. Therefore, without IPv6\n\t * extension headers (none here), the outer IPv6 payload_len\n\t * is equal to the inner IPv4 tot_len.\n\t */"
    },
    {
      "start_line": 292,
      "end_line": 294,
      "text": "/* We need to change skb->protocol and the corresponding packet\n\t * field because the L3 protocol will now be IPv6.\n\t */"
    },
    {
      "start_line": 300,
      "end_line": 305,
      "text": "/* ctx_change_proto above grows the packet from IPv4 header\n\t * length to IPv6 header length. It adds the additional space\n\t * before the inner L3 header, in the same place we will later\n\t * add the outer IPv6 header.\n\t * Thus, deduce this space from the next packet growth.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " union v6addr *src_sid",
    " struct in6_addr *dst_sid"
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
    "static __always_inline int srv6_handling4 (struct  __ctx_buff *ctx, union v6addr *src_sid, struct in6_addr *dst_sid)\n",
    "{\n",
    "    __u16 new_payload_len, outer_proto = bpf_htons (ETH_P_IPV6);\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    __u8 nexthdr;\n",
    "    int growth;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return DROP_INVALID;\n",
    "    nexthdr = IPPROTO_IPIP;\n",
    "    new_payload_len = bpf_ntohs (ip4->tot_len) - (__u16) (ip4->ihl << 2) + sizeof (struct iphdr);\n",
    "    if (ctx_change_proto (ctx, outer_proto, 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    if (ctx_store_bytes (ctx, offsetof (struct ethhdr, h_proto), &outer_proto, sizeof (outer_proto), 0) < 0)\n",
    "        return DROP_WRITE_ERROR;\n",
    "    growth = sizeof (struct iphdr);\n",
    "    return srv6_encapsulation (ctx, growth, new_payload_len, nexthdr, src_sid, dst_sid);\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "srv6_encapsulation",
    "bpf_ntohs",
    "ctx_store_bytes",
    "offsetof",
    "ctx_change_proto",
    "bpf_htons"
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
srv6_handling4(struct __ctx_buff *ctx, union v6addr *src_sid,
	       struct in6_addr *dst_sid)
{
	__u16 new_payload_len, outer_proto = bpf_htons(ETH_P_IPV6);
	void *data, *data_end;
	struct iphdr *ip4;
	__u8 nexthdr;
	int growth;

	/* Inner packet is IPv4. */
	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	nexthdr = IPPROTO_IPIP;
	/* IPv4's tot_len fields has the size of the entire packet
	 * including headers while IPv6's payload_len field has only
	 * the size of the IPv6 payload. Therefore, without IPv6
	 * extension headers (none here), the outer IPv6 payload_len
	 * is equal to the inner IPv4 tot_len.
	 */
	new_payload_len = bpf_ntohs(ip4->tot_len) - (__u16)(ip4->ihl << 2) + sizeof(struct iphdr);

	/* We need to change skb->protocol and the corresponding packet
	 * field because the L3 protocol will now be IPv6.
	 */
	if (ctx_change_proto(ctx, outer_proto, 0) < 0)
		return DROP_WRITE_ERROR;
	if (ctx_store_bytes(ctx, offsetof(struct ethhdr, h_proto),
			    &outer_proto, sizeof(outer_proto), 0) < 0)
		return DROP_WRITE_ERROR;
	/* ctx_change_proto above grows the packet from IPv4 header
	 * length to IPv6 header length. It adds the additional space
	 * before the inner L3 header, in the same place we will later
	 * add the outer IPv6 header.
	 * Thus, deduce this space from the next packet growth.
	 */
	growth = sizeof(struct iphdr);

	return srv6_encapsulation(ctx, growth, new_payload_len, nexthdr,
				  src_sid, dst_sid);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 312,
  "endLine": 331,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_handling6",
  "developer_inline_comments": [
    {
      "start_line": 322,
      "end_line": 322,
      "text": "/* Inner packet is IPv6. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " union v6addr *src_sid",
    " struct in6_addr *dst_sid"
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
    "static __always_inline int srv6_handling6 (struct  __ctx_buff *ctx, union v6addr *src_sid, struct in6_addr *dst_sid)\n",
    "{\n",
    "    __u16 new_payload_len;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    __u8 nexthdr;\n",
    "    int growth;\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return DROP_INVALID;\n",
    "    nexthdr = IPPROTO_IPV6;\n",
    "    new_payload_len = bpf_ntohs (ip6->payload_len) + sizeof (struct ipv6hdr);\n",
    "    growth = sizeof (struct ipv6hdr);\n",
    "    return srv6_encapsulation (ctx, growth, new_payload_len, nexthdr, src_sid, dst_sid);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "revalidate_data",
    "srv6_encapsulation"
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
srv6_handling6(struct __ctx_buff *ctx, union v6addr *src_sid,
	       struct in6_addr *dst_sid)
{
	__u16 new_payload_len;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u8 nexthdr;
	int growth;

	/* Inner packet is IPv6. */
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
	nexthdr = IPPROTO_IPV6;
	new_payload_len = bpf_ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
	growth = sizeof(struct ipv6hdr);

	return srv6_encapsulation(ctx, growth, new_payload_len, nexthdr,
				  src_sid, dst_sid);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 333,
  "endLine": 373,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_handling",
  "developer_inline_comments": [
    {
      "start_line": 356,
      "end_line": 356,
      "text": "/* ENABLE_IPV6 */"
    },
    {
      "start_line": 369,
      "end_line": 369,
      "text": "/* ENABLE_IPV4 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 vrf_id",
    " struct in6_addr *dst_sid"
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
    "static __always_inline int srv6_handling (struct  __ctx_buff *ctx, __u32 vrf_id, struct in6_addr *dst_sid)\n",
    "{\n",
    "    union v6addr *src_sid;\n",
    "    void *data, *data_end;\n",
    "    __u16 inner_proto;\n",
    "    if (!validate_ethertype (ctx, &inner_proto))\n",
    "        return DROP_UNSUPPORTED_L2;\n",
    "    switch (inner_proto) {\n",
    "\n",
    "#  ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        {\n",
    "            struct ipv6hdr *ip6;\n",
    "            if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "                return DROP_INVALID;\n",
    "            src_sid = srv6_lookup_policy6 (vrf_id, & ip6 -> saddr);\n",
    "            if (!src_sid)\n",
    "                return DROP_NO_SID;\n",
    "            return srv6_handling6 (ctx, src_sid, dst_sid);\n",
    "        }\n",
    "\n",
    "#  endif /* ENABLE_IPV6 */\n",
    "\n",
    "#  ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        {\n",
    "            struct iphdr *ip4;\n",
    "            if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "                return DROP_INVALID;\n",
    "            src_sid = srv6_lookup_policy4 (vrf_id, ip4 -> saddr);\n",
    "            if (!src_sid)\n",
    "                return DROP_NO_SID;\n",
    "            return srv6_handling4 (ctx, src_sid, dst_sid);\n",
    "        }\n",
    "\n",
    "#  endif /* ENABLE_IPV4 */\n",
    "    default :\n",
    "        return DROP_INVALID;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "srv6_lookup_policy4",
    "validate_ethertype",
    "srv6_lookup_policy6",
    "srv6_handling4",
    "srv6_handling6",
    "bpf_htons"
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
srv6_handling(struct __ctx_buff *ctx, __u32 vrf_id, struct in6_addr *dst_sid)
{
	union v6addr *src_sid;
	void *data, *data_end;
	__u16 inner_proto;

	if (!validate_ethertype(ctx, &inner_proto))
		return DROP_UNSUPPORTED_L2;

	switch (inner_proto) {
#  ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6hdr *ip6;

		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		src_sid = srv6_lookup_policy6(vrf_id, &ip6->saddr);
		if (!src_sid)
			return DROP_NO_SID;
		return srv6_handling6(ctx, src_sid, dst_sid);
	}
#  endif /* ENABLE_IPV6 */
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct iphdr *ip4;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		src_sid = srv6_lookup_policy4(vrf_id, ip4->saddr);
		if (!src_sid)
			return DROP_NO_SID;
		return srv6_handling4(ctx, src_sid, dst_sid);
	}
#  endif /* ENABLE_IPV4 */
	default:
		return DROP_INVALID;
	}
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
  "startLine": 375,
  "endLine": 413,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_reply",
  "developer_inline_comments": [
    {
      "start_line": 409,
      "end_line": 409,
      "text": "/* ENABLE_IPV4 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline int srv6_reply (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct srv6_ipv6_2tuple *outer_ips;\n",
    "    struct iphdr * ip4 __maybe_unused;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return DROP_UNSUPPORTED_L2;\n",
    "    switch (proto) {\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "            return DROP_INVALID;\n",
    "        outer_ips = srv6_lookup_state_entry6 (ip6);\n",
    "        if (!outer_ips)\n",
    "            return DROP_MISSING_SRV6_STATE;\n",
    "        return srv6_handling6 (ctx, &outer_ips->src, (struct in6_addr *) &outer_ips->dst);\n",
    "\n",
    "#  ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "            return DROP_INVALID;\n",
    "        outer_ips = srv6_lookup_state_entry4 (ip4);\n",
    "        if (!outer_ips)\n",
    "            return DROP_MISSING_SRV6_STATE;\n",
    "        return srv6_handling4 (ctx, &outer_ips->src, (struct in6_addr *) &outer_ips->dst);\n",
    "\n",
    "#  endif /* ENABLE_IPV4 */\n",
    "    }\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "revalidate_data",
    "srv6_lookup_state_entry6",
    "validate_ethertype",
    "srv6_lookup_state_entry4",
    "srv6_handling4",
    "srv6_handling6",
    "bpf_htons"
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
srv6_reply(struct __ctx_buff *ctx)
{
	struct srv6_ipv6_2tuple *outer_ips;
	struct iphdr *ip4 __maybe_unused;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry6(ip6);
		if (!outer_ips)
			return DROP_MISSING_SRV6_STATE;

		return srv6_handling6(ctx, &outer_ips->src,
				      (struct in6_addr *)&outer_ips->dst);
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		outer_ips = srv6_lookup_state_entry4(ip4);
		if (!outer_ips)
			return DROP_MISSING_SRV6_STATE;

		return srv6_handling4(ctx, &outer_ips->src,
				      (struct in6_addr *)&outer_ips->dst);
#  endif /* ENABLE_IPV4 */
	}

	return CTX_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 415,
  "endLine": 422,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_load_meta_sid",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct in6_addr *sid"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void srv6_load_meta_sid (struct  __ctx_buff *ctx, struct in6_addr *sid)\n",
    "{\n",
    "    sid->s6_addr32[0] = ctx_load_meta (ctx, CB_SRV6_SID_1);\n",
    "    sid->s6_addr32[1] = ctx_load_meta (ctx, CB_SRV6_SID_2);\n",
    "    sid->s6_addr32[2] = ctx_load_meta (ctx, CB_SRV6_SID_3);\n",
    "    sid->s6_addr32[3] = ctx_load_meta (ctx, CB_SRV6_SID_4);\n",
    "}\n"
  ],
  "called_function_list": [
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
srv6_load_meta_sid(struct __ctx_buff *ctx, struct in6_addr *sid)
{
	sid->s6_addr32[0] = ctx_load_meta(ctx, CB_SRV6_SID_1);
	sid->s6_addr32[1] = ctx_load_meta(ctx, CB_SRV6_SID_2);
	sid->s6_addr32[2] = ctx_load_meta(ctx, CB_SRV6_SID_3);
	sid->s6_addr32[3] = ctx_load_meta(ctx, CB_SRV6_SID_4);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 424,
  "endLine": 431,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "srv6_store_meta_sid",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const union v6addr *sid"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void srv6_store_meta_sid (struct  __ctx_buff *ctx, const union v6addr *sid)\n",
    "{\n",
    "    ctx_store_meta (ctx, CB_SRV6_SID_1, sid->p1);\n",
    "    ctx_store_meta (ctx, CB_SRV6_SID_2, sid->p2);\n",
    "    ctx_store_meta (ctx, CB_SRV6_SID_3, sid->p3);\n",
    "    ctx_store_meta (ctx, CB_SRV6_SID_4, sid->p4);\n",
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
static __always_inline void
srv6_store_meta_sid(struct __ctx_buff *ctx, const union v6addr *sid)
{
	ctx_store_meta(ctx, CB_SRV6_SID_1, sid->p1);
	ctx_store_meta(ctx, CB_SRV6_SID_2, sid->p2);
	ctx_store_meta(ctx, CB_SRV6_SID_3, sid->p3);
	ctx_store_meta(ctx, CB_SRV6_SID_4, sid->p4);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_ENCAP)
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
  "startLine": 434,
  "endLine": 452,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "tail_srv6_encap",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_srv6_encap (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct in6_addr dst_sid;\n",
    "    __u32 vrf_id;\n",
    "    int ret = 0;\n",
    "    srv6_load_meta_sid (ctx, &dst_sid);\n",
    "    vrf_id = ctx_load_meta (ctx, CB_SRV6_VRF_ID);\n",
    "    ret = srv6_handling (ctx, vrf_id, & dst_sid);\n",
    "    if (ret < 0)\n",
    "        return send_drop_notify_error (ctx, SECLABEL, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "    send_trace_notify (ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "srv6_load_meta_sid",
    "send_trace_notify",
    "srv6_handling",
    "ctx_load_meta",
    "send_drop_notify_error"
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
int tail_srv6_encap(struct __ctx_buff *ctx)
{
	struct in6_addr dst_sid;
	__u32 vrf_id;
	int ret = 0;

	srv6_load_meta_sid(ctx, &dst_sid);
	vrf_id = ctx_load_meta(ctx, CB_SRV6_VRF_ID);

	ret = srv6_handling(ctx, vrf_id, &dst_sid);

	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0,
			  TRACE_REASON_UNKNOWN, 0);
	return CTX_ACT_OK;
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_DECAP)
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
  "startLine": 455,
  "endLine": 473,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "tail_srv6_decap",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_srv6_decap (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = 0;\n",
    "    ret = srv6_create_state_entry (ctx);\n",
    "    if (ret < 0)\n",
    "        goto error_drop;\n",
    "    ret = srv6_decapsulation (ctx);\n",
    "    if (ret < 0)\n",
    "        goto error_drop;\n",
    "    send_trace_notify (ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0, TRACE_REASON_UNKNOWN, 0);\n",
    "    return CTX_ACT_OK;\n",
    "error_drop :\n",
    "    return send_drop_notify_error (ctx, SECLABEL, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "send_trace_notify",
    "send_drop_notify_error",
    "srv6_create_state_entry",
    "srv6_decapsulation"
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
int tail_srv6_decap(struct __ctx_buff *ctx)
{
	int ret = 0;

	ret = srv6_create_state_entry(ctx);
	if (ret < 0)
		goto error_drop;

	ret = srv6_decapsulation(ctx);
	if (ret < 0)
		goto error_drop;

	send_trace_notify(ctx, TRACE_TO_STACK, SECLABEL, 0, 0, 0,
			  TRACE_REASON_UNKNOWN, 0);
	return CTX_ACT_OK;
error_drop:
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
}

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_SRV6_REPLY)
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
  "startLine": 476,
  "endLine": 485,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/egress_policies.h",
  "funcName": "tail_srv6_reply",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "CTX_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
  ],
  "source": [
    "int tail_srv6_reply (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret;\n",
    "    ret = srv6_reply (ctx);\n",
    "    if (ret < 0)\n",
    "        return send_drop_notify_error (ctx, SECLABEL, ret, CTX_ACT_DROP, METRIC_EGRESS);\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "srv6_reply",
    "send_drop_notify_error"
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
int tail_srv6_reply(struct __ctx_buff *ctx)
{
	int ret;

	ret = srv6_reply(ctx);
	if (ret < 0)
		return send_drop_notify_error(ctx, SECLABEL, ret, CTX_ACT_DROP,
					      METRIC_EGRESS);
	return CTX_ACT_OK;
}
# endif /* SKIP_SRV6_HANDLING */
#endif /* ENABLE_SRV6 */
#endif /* __LIB_EGRESS_POLICIES_H_ */
