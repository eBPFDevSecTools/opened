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
      "text": "/* From XDP layer, we neither go through an egress hook nor qdisc\n * from here, hence nothing to be set.\n */"
    },
    {
      "start_line": 20,
      "end_line": 20,
      "text": "/* 16 bit as current used aggregate, and preserved in host ns. */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 aggregate"
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
    "static __always_inline void edt_set_aggregate (struct  __ctx_buff *ctx, __u32 aggregate)\n",
    "{\n",
    "    ctx->queue_mapping = aggregate;\n",
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
  "developer_inline_comments": [
    {
      "start_line": 28,
      "end_line": 30,
      "text": "/* We need to reset queue mapping here such that new mapping will\n\t * be performed based on skb hash. See netdev_pick_tx().\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inline__u32",
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
    "static __always_inline __u32 edt_get_aggregate (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 aggregate = ctx->queue_mapping;\n",
    "    ctx->queue_mapping = 0;\n",
    "    return aggregate;\n",
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
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
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
    },
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
  "startLine": 36,
  "endLine": 77,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/edt.h",
  "funcName": "edt_sched_departure",
  "developer_inline_comments": [
    {
      "start_line": 67,
      "end_line": 71,
      "text": "/* FQ implements a drop horizon, see also 39d010504e6b (\"net_sched:\n\t * sch_fq: add horizon attribute\"). However, we explicitly need the\n\t * drop horizon here to i) avoid having t_last messed up and ii) to\n\t * potentially allow for per aggregate control.\n\t */"
    }
  ],
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
    "CTX_ACT_OK",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp"
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
  "called_function_list": [
    "READ_ONCE",
    "ctx_wire_len",
    "edt_get_aggregate",
    "validate_ethertype",
    "WRITE_ONCE",
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u32 aggregate __maybe_unused"
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
    "static __always_inline void edt_set_aggregate (struct  __ctx_buff * ctx __maybe_unused, __u32 aggregate __maybe_unused)\n",
    "{\n",
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
static __always_inline void
edt_set_aggregate(struct __ctx_buff *ctx __maybe_unused,
		  __u32 aggregate __maybe_unused)
{
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
#endif /* __EDT_H_ */
