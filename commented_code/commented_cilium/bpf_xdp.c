// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/xdp.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>
#include <filter_config.h>

#define SKIP_POLICY_MAP 1

/* Controls the inclusion of the CILIUM_CALL_HANDLE_ICMP6_NS section in the
 * bpf_lxc object file.
 */
#define SKIP_ICMPV6_NS_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_TIME_EXCEEDED section
 * in the bpf_lxc object file. This is needed for all callers of
 * ipv6_local_delivery, which calls into the IPv6 L3 handling.
 */
#define SKIP_ICMPV6_HOPLIMIT_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SEND_ICMP6_ECHO_REPLY section in
 * the bpf_lxc object file.
 */
#define SKIP_ICMPV6_ECHO_HANDLING

/* Controls the inclusion of the CILIUM_CALL_SRV6 section in the object file.
 */
#define SKIP_SRV6_HANDLING

/* The XDP datapath does not take care of health probes from the local node,
 * thus do not compile it in.
 */
#undef ENABLE_HEALTH_CHECK

#include "lib/common.h"
#include "lib/maps.h"
#include "lib/eps.h"
#include "lib/events.h"
#include "lib/nodeport.h"

#ifdef ENABLE_PREFILTER
#ifndef HAVE_LPM_TRIE_MAP_TYPE
# undef CIDR4_LPM_PREFILTER
# undef CIDR6_LPM_PREFILTER
#endif

#ifdef CIDR4_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR4_HMAP_NAME __section_maps_btf;

#ifdef CIDR4_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR4_LMAP_NAME __section_maps_btf;

#endif /* CIDR4_LPM_PREFILTER */
#endif /* CIDR4_FILTER */

#ifdef CIDR6_FILTER
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_HMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR6_HMAP_NAME __section_maps_btf;

#ifdef CIDR6_LPM_PREFILTER
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v6_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CIDR4_LMAP_ELEMS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CIDR6_LMAP_NAME __section_maps_btf;
#endif /* CIDR6_LPM_PREFILTER */
#endif /* CIDR6_FILTER */
#endif /* ENABLE_PREFILTER */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 96,
  "endLine": 117,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "bpf_xdp_exit",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const int verdict"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused int bpf_xdp_exit (struct  __ctx_buff *ctx, const int verdict)\n",
    "{\n",
    "    if (verdict == CTX_ACT_OK) {\n",
    "        __u32 meta_xfer = ctx_load_meta (ctx, XFER_MARKER);\n",
    "        if (meta_xfer) {\n",
    "            if (!ctx_adjust_meta (ctx, -(int) sizeof (meta_xfer))) {\n",
    "                __u32 *data_meta = ctx_data_meta (ctx);\n",
    "                __u32 *data = ctx_data (ctx);\n",
    "                if (!ctx_no_room (data_meta + 1, data))\n",
    "                    data_meta[0] = meta_xfer;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return verdict;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
bpf_xdp_exit(struct __ctx_buff *ctx, const int verdict)
{
	if (verdict == CTX_ACT_OK) {
		__u32 meta_xfer = ctx_load_meta(ctx, XFER_MARKER);

		/* We transfer data from XFER_MARKER. This specifically
		 * does not break packet trains in GRO.
		 */
		if (meta_xfer) {
			if (!ctx_adjust_meta(ctx, -(int)sizeof(meta_xfer))) {
				__u32 *data_meta = ctx_data_meta(ctx);
				__u32 *data = ctx_data(ctx);

				if (!ctx_no_room(data_meta + 1, data))
					data_meta[0] = meta_xfer;
			}
		}
	}

	return verdict;
}

#ifdef ENABLE_IPV4
#ifdef ENABLE_NODEPORT_ACCELERATION
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV4_FROM_NETDEV)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_NETDEV"
        ]
      }
    ]
  },
  "startLine": 122,
  "endLine": 140,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "tail_lb_ipv4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "int tail_lb_ipv4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    if (!bpf_skip_nodeport (ctx)) {\n",
    "        ret = nodeport_lb4 (ctx, 0);\n",
    "        if (ret == NAT_46X64_RECIRC) {\n",
    "            ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "            return send_drop_notify_error (ctx, 0, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "        }\n",
    "        else if (IS_ERR (ret)) {\n",
    "            return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "        }\n",
    "    }\n",
    "    return bpf_xdp_exit (ctx, ret);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
int tail_lb_ipv4(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;

	if (!bpf_skip_nodeport(ctx)) {
		ret = nodeport_lb4(ctx, 0);
		if (ret == NAT_46X64_RECIRC) {
			ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
			return send_drop_notify_error(ctx, 0, DROP_MISSED_TAIL_CALL,
						      CTX_ACT_DROP,
						      METRIC_INGRESS);
		} else if (IS_ERR(ret)) {
			return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
						      METRIC_INGRESS);
		}
	}

	return bpf_xdp_exit(ctx, ret);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tep_ctx",
          " CILIUM_CALL_IPV4_FROM_NETDEV"
        ]
      }
    ]
  },
  "startLine": 142,
  "endLine": 147,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v4_lb",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v4_lb (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    ep_tail_call (ctx, CILIUM_CALL_IPV4_FROM_NETDEV);\n",
    "    return send_drop_notify_error (ctx, 0, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v4_lb(struct __ctx_buff *ctx)
{
	ep_tail_call(ctx, CILIUM_CALL_IPV4_FROM_NETDEV);
	return send_drop_notify_error(ctx, 0, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP,
				      METRIC_INGRESS);
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 149,
  "endLine": 152,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v4_lb",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v4_lb (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v4_lb(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
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
          "#ifdef CIDR4_LPM_PREFILTER\tif &CIDR4_LMAP_NAME",
          " &pfx\t\treturn CTX_ACT_DROP"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#endif \treturn &CIDR4_HMAP_NAME",
          " &pfx ?\t\tCTX_ACT_DROP : check_v4_lbctx"
        ]
      }
    ]
  },
  "startLine": 156,
  "endLine": 179,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v4",
  "updateMaps": [],
  "readMaps": [
    " CIDR4_LMAP_NAME",
    " CIDR4_HMAP_NAME"
  ],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    struct iphdr *ipv4_hdr = data + sizeof (struct ethhdr);\n",
    "    struct lpm_v4_key pfx __maybe_unused;\n",
    "    if (ctx_no_room (ipv4_hdr + 1, data_end))\n",
    "        return CTX_ACT_DROP;\n",
    "\n",
    "#ifdef CIDR4_FILTER\n",
    "    memcpy (pfx.lpm.data, &ipv4_hdr->saddr, sizeof (pfx.addr));\n",
    "    pfx.lpm.prefixlen = 32;\n",
    "\n",
    "#ifdef CIDR4_LPM_PREFILTER\n",
    "    if (map_lookup_elem (&CIDR4_LMAP_NAME, &pfx))\n",
    "        return CTX_ACT_DROP;\n",
    "\n",
    "#endif /* CIDR4_LPM_PREFILTER */\n",
    "    return map_lookup_elem (&CIDR4_HMAP_NAME, &pfx) ? CTX_ACT_DROP : check_v4_lb (ctx);\n",
    "\n",
    "#else\n",
    "    return check_v4_lb (ctx);\n",
    "\n",
    "#endif /* CIDR4_FILTER */\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct lpm_v4_key pfx __maybe_unused;

	if (ctx_no_room(ipv4_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR4_FILTER
	memcpy(pfx.lpm.data, &ipv4_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 32;

#ifdef CIDR4_LPM_PREFILTER
	if (map_lookup_elem(&CIDR4_LMAP_NAME, &pfx))
		return CTX_ACT_DROP;
#endif /* CIDR4_LPM_PREFILTER */
	return map_lookup_elem(&CIDR4_HMAP_NAME, &pfx) ?
		CTX_ACT_DROP : check_v4_lb(ctx);
#else
	return check_v4_lb(ctx);
#endif /* CIDR4_FILTER */
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 181,
  "endLine": 184,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v4 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return check_v4_lb (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v4(struct __ctx_buff *ctx)
{
	return check_v4_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
#ifdef ENABLE_NODEPORT_ACCELERATION
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_IPV6_FROM_NETDEV)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 191,
  "endLine": 203,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "tail_lb_ipv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "int tail_lb_ipv6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    if (!bpf_skip_nodeport (ctx)) {\n",
    "        ret = nodeport_lb6 (ctx, 0);\n",
    "        if (IS_ERR (ret))\n",
    "            return send_drop_notify_error (ctx, 0, ret, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "    }\n",
    "    return bpf_xdp_exit (ctx, ret);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
int tail_lb_ipv6(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;

	if (!bpf_skip_nodeport(ctx)) {
		ret = nodeport_lb6(ctx, 0);
		if (IS_ERR(ret))
			return send_drop_notify_error(ctx, 0, ret, CTX_ACT_DROP,
						      METRIC_INGRESS);
	}

	return bpf_xdp_exit(ctx, ret);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tep_ctx",
          " CILIUM_CALL_IPV6_FROM_NETDEV"
        ]
      }
    ]
  },
  "startLine": 205,
  "endLine": 210,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v6_lb",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v6_lb (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    ep_tail_call (ctx, CILIUM_CALL_IPV6_FROM_NETDEV);\n",
    "    return send_drop_notify_error (ctx, 0, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP, METRIC_INGRESS);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v6_lb(struct __ctx_buff *ctx)
{
	ep_tail_call(ctx, CILIUM_CALL_IPV6_FROM_NETDEV);
	return send_drop_notify_error(ctx, 0, DROP_MISSED_TAIL_CALL, CTX_ACT_DROP,
				      METRIC_INGRESS);
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 212,
  "endLine": 215,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v6_lb",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v6_lb (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    return CTX_ACT_OK;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v6_lb(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#endif /* ENABLE_NODEPORT_ACCELERATION */

#ifdef ENABLE_PREFILTER
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
          "#ifdef CIDR6_LPM_PREFILTER\tif &CIDR6_LMAP_NAME",
          " &pfx\t\treturn CTX_ACT_DROP"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "#endif \treturn &CIDR6_HMAP_NAME",
          " &pfx ?\t\tCTX_ACT_DROP : check_v6_lbctx"
        ]
      }
    ]
  },
  "startLine": 219,
  "endLine": 242,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v6",
  "updateMaps": [],
  "readMaps": [
    " CIDR6_LMAP_NAME",
    " CIDR6_HMAP_NAME"
  ],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    void *data = ctx_data (ctx);\n",
    "    struct ipv6hdr *ipv6_hdr = data + sizeof (struct ethhdr);\n",
    "    struct lpm_v6_key pfx __maybe_unused;\n",
    "    if (ctx_no_room (ipv6_hdr + 1, data_end))\n",
    "        return CTX_ACT_DROP;\n",
    "\n",
    "#ifdef CIDR6_FILTER\n",
    "    __bpf_memcpy_builtin (pfx.lpm.data, &ipv6_hdr->saddr, sizeof (pfx.addr));\n",
    "    pfx.lpm.prefixlen = 128;\n",
    "\n",
    "#ifdef CIDR6_LPM_PREFILTER\n",
    "    if (map_lookup_elem (&CIDR6_LMAP_NAME, &pfx))\n",
    "        return CTX_ACT_DROP;\n",
    "\n",
    "#endif /* CIDR6_LPM_PREFILTER */\n",
    "    return map_lookup_elem (&CIDR6_HMAP_NAME, &pfx) ? CTX_ACT_DROP : check_v6_lb (ctx);\n",
    "\n",
    "#else\n",
    "    return check_v6_lb (ctx);\n",
    "\n",
    "#endif /* CIDR6_FILTER */\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct ipv6hdr *ipv6_hdr = data + sizeof(struct ethhdr);
	struct lpm_v6_key pfx __maybe_unused;

	if (ctx_no_room(ipv6_hdr + 1, data_end))
		return CTX_ACT_DROP;

#ifdef CIDR6_FILTER
	__bpf_memcpy_builtin(pfx.lpm.data, &ipv6_hdr->saddr, sizeof(pfx.addr));
	pfx.lpm.prefixlen = 128;

#ifdef CIDR6_LPM_PREFILTER
	if (map_lookup_elem(&CIDR6_LMAP_NAME, &pfx))
		return CTX_ACT_DROP;
#endif /* CIDR6_LPM_PREFILTER */
	return map_lookup_elem(&CIDR6_HMAP_NAME, &pfx) ?
		CTX_ACT_DROP : check_v6_lb(ctx);
#else
	return check_v6_lb(ctx);
#endif /* CIDR6_FILTER */
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 244,
  "endLine": 247,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_v6 (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return check_v6_lb (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_v6(struct __ctx_buff *ctx)
{
	return check_v6_lb(ctx);
}
#endif /* ENABLE_PREFILTER */
#endif /* ENABLE_IPV6 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 251,
  "endLine": 278,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "check_filters",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline int check_filters (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    int ret = CTX_ACT_OK;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return CTX_ACT_OK;\n",
    "    ctx_store_meta (ctx, XFER_MARKER, 0);\n",
    "    bpf_skip_nodeport_clear (ctx);\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ret = check_v4 (ctx);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ret = check_v6 (ctx);\n",
    "        break;\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    return bpf_xdp_exit (ctx, ret);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
static __always_inline int check_filters(struct __ctx_buff *ctx)
{
	int ret = CTX_ACT_OK;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;

	ctx_store_meta(ctx, XFER_MARKER, 0);
	bpf_skip_nodeport_clear(ctx);

	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = check_v4(ctx);
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = check_v6(ctx);
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}

	return bpf_xdp_exit(ctx, ret);
}

__section("from-netdev")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 281,
  "endLine": 284,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_xdp.c",
  "funcName": "bpf_xdp_entry",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "int bpf_xdp_entry (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return check_filters (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
int bpf_xdp_entry(struct __ctx_buff *ctx)
{
	return check_filters(ctx);
}

BPF_LICENSE("Dual BSD/GPL");
