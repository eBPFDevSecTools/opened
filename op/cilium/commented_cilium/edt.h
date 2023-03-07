/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __EDT_H_
#define __EDT_H_

#include <bpf/ctx/ctx.h>

#include "common.h"
#include "time.h"
#include "maps.h"

/* From XDP layer, we neither go through an egress hook nor qdisc
 * from here, hence nothing to be set.
 */
#if defined(ENABLE_BANDWIDTH_MANAGER) && __ctx_is == __ctx_skb
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 17,
  "endLine": 22,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/edt.h",
  "funcName": "edt_set_aggregate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 aggregate"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline void edt_set_aggregate (struct  __ctx_buff *ctx, __u32 aggregate)\n",
    "{\n",
    "    ctx->queue_mapping = aggregate;\n",
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
static __always_inline void edt_set_aggregate(struct __ctx_buff *ctx,
					      __u32 aggregate)
{
	/* 16 bit as current used aggregate, and preserved in host ns. */
	ctx->queue_mapping = aggregate;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 34,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/edt.h",
  "funcName": "edt_get_aggregate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline __u32 edt_get_aggregate (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 aggregate = ctx->queue_mapping;\n",
    "    ctx->queue_mapping = 0;\n",
    "    return aggregate;\n",
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
static __always_inline __u32 edt_get_aggregate(struct __ctx_buff *ctx)
{
	__u32 aggregate = ctx->queue_mapping;

	/* We need to reset queue mapping here such that new mapping will
	 * be performed based on skb hash. See netdev_pick_tx().
	 */
	ctx->queue_mapping = 0;

	return aggregate;
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
          ]
        }
      ]
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\tinfo ",
        "inpVar": [
          " &THROTTLE_MAP",
          " &aggregate"
        ]
      }
    ],
    "ktime_get_ns": [
      {
        "opVar": "\tnow ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 36,
  "endLine": 77,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/edt.h",
  "funcName": "edt_sched_departure",
  "updateMaps": [],
  "readMaps": [
    "  THROTTLE_MAP"
  ],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "ktime_get_ns",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline int edt_sched_departure (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u64 delay, now, t, t_next;\n",
    "    struct edt_id aggregate;\n",
    "    struct edt_info *info;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return CTX_ACT_OK;\n",
    "    if (proto != bpf_htons (ETH_P_IP) && proto != bpf_htons (ETH_P_IPV6))\n",
    "        return CTX_ACT_OK;\n",
    "    aggregate.id = edt_get_aggregate (ctx);\n",
    "    if (!aggregate.id)\n",
    "        return CTX_ACT_OK;\n",
    "    info = map_lookup_elem (& THROTTLE_MAP, & aggregate);\n",
    "    if (!info)\n",
    "        return CTX_ACT_OK;\n",
    "    now = ktime_get_ns ();\n",
    "    t = ctx->tstamp;\n",
    "    if (t < now)\n",
    "        t = now;\n",
    "    delay = ((__u64) ctx_wire_len (ctx)) * NSEC_PER_SEC / info->bps;\n",
    "    t_next = READ_ONCE (info->t_last) + delay;\n",
    "    if (t_next <= t) {\n",
    "        WRITE_ONCE (info->t_last, t);\n",
    "        return CTX_ACT_OK;\n",
    "    }\n",
    "    if (t_next - now >= info->t_horizon_drop)\n",
    "        return CTX_ACT_DROP;\n",
    "    WRITE_ONCE (info->t_last, t_next);\n",
    "    ctx->tstamp = t_next;\n",
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
static __always_inline int edt_sched_departure(struct __ctx_buff *ctx)
{
	__u64 delay, now, t, t_next;
	struct edt_id aggregate;
	struct edt_info *info;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return CTX_ACT_OK;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return CTX_ACT_OK;

	aggregate.id = edt_get_aggregate(ctx);
	if (!aggregate.id)
		return CTX_ACT_OK;

	info = map_lookup_elem(&THROTTLE_MAP, &aggregate);
	if (!info)
		return CTX_ACT_OK;

	now = ktime_get_ns();
	t = ctx->tstamp;
	if (t < now)
		t = now;
	delay = ((__u64)ctx_wire_len(ctx)) * NSEC_PER_SEC / info->bps;
	t_next = READ_ONCE(info->t_last) + delay;
	if (t_next <= t) {
		WRITE_ONCE(info->t_last, t);
		return CTX_ACT_OK;
	}
	/* FQ implements a drop horizon, see also 39d010504e6b ("net_sched:
	 * sch_fq: add horizon attribute"). However, we explicitly need the
	 * drop horizon here to i) avoid having t_last messed up and ii) to
	 * potentially allow for per aggregate control.
	 */
	if (t_next - now >= info->t_horizon_drop)
		return CTX_ACT_DROP;
	WRITE_ONCE(info->t_last, t_next);
	ctx->tstamp = t_next;
	return CTX_ACT_OK;
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 79,
  "endLine": 83,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/edt.h",
  "funcName": "edt_set_aggregate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u32 aggregate __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "lwt_out",
    "cgroup_device",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "lwt_in",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "lwt_seg6local",
    "tracepoint",
    "perf_event",
    "sk_msg",
    "cgroup_sock",
    "kprobe",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __always_inline void edt_set_aggregate (struct  __ctx_buff * ctx __maybe_unused, __u32 aggregate __maybe_unused)\n",
    "{\n",
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
static __always_inline void
edt_set_aggregate(struct __ctx_buff *ctx __maybe_unused,
		  __u32 aggregate __maybe_unused)
{
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
#endif /* __EDT_H_ */
