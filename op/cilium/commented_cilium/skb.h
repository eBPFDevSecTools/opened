/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CTX_SKB_H_
#define __BPF_CTX_SKB_H_

#define __ctx_buff		__sk_buff
#define __ctx_is		__ctx_skb

#include "common.h"
#include "../helpers_skb.h"

#ifndef TC_ACT_OK
# define TC_ACT_OK		0
#endif

#ifndef TC_ACT_SHOT
# define TC_ACT_SHOT		2
#endif

#ifndef TC_ACT_REDIRECT
# define TC_ACT_REDIRECT	7
#endif

#define CTX_ACT_OK		TC_ACT_OK
#define CTX_ACT_DROP		TC_ACT_SHOT
#define CTX_ACT_TX		TC_ACT_REDIRECT
#define CTX_ACT_REDIRECT	TC_ACT_REDIRECT

/* Discouraged since prologue will unclone full skb. */
#define CTX_DIRECT_WRITE_OK	0

#define META_PIVOT		field_sizeof(struct __sk_buff, cb)

#define ctx_load_bytes		skb_load_bytes
#define ctx_store_bytes		skb_store_bytes

#define ctx_adjust_hroom	skb_adjust_room

#define ctx_change_type		skb_change_type
#define ctx_change_proto	skb_change_proto
#define ctx_change_tail		skb_change_tail

#define ctx_pull_data		skb_pull_data

#define ctx_get_tunnel_key	skb_get_tunnel_key
#define ctx_set_tunnel_key	skb_set_tunnel_key

#define ctx_event_output	skb_event_output

#define ctx_adjust_meta		({ -ENOTSUPP; })

/* Avoid expensive calls into the kernel flow dissector if it's not an L4
 * hash. We currently only use the hash for debugging. If needed later, we
 * can map it to BPF_FUNC(get_hash_recalc) to get the L4 hash.
 */
#define get_hash(ctx)		ctx->hash
#define get_hash_recalc(ctx)	get_hash(ctx)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx_const struct __sk_buff *ctx __maybe_unused",
          " int ifindex",
          " __u32 flags"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn ifindex",
          " flags"
        ]
      }
    ]
  },
  "startLine": 60,
  "endLine": 64,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_redirect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff * ctx __maybe_unused",
    " int ifindex",
    " __u32 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
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
ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	return redirect(ifindex, flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx__peerconst struct __sk_buff *ctx __maybe_unused",
          " int ifindex",
          " __u32 flags"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn _peerifindex",
          " flags"
        ]
      }
    ]
  },
  "startLine": 66,
  "endLine": 70,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_redirect_peer",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff * ctx __maybe_unused",
    " int ifindex",
    " __u32 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
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
ctx_redirect_peer(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	return redirect_peer(ifindex, flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Resize (trim or grow) the packet associated to <[ skb ]>(IP: 0) to the new len. The <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. The basic idea is that the helper performs the needed work to change the size of the packet , then the eBPF program rewrites the rest via helpers like skb_store_bytes() , l3_csum_replace() , l3_csum_replace() and others. This helper is a slow path utility intended for replies with control messages. And because it is targeted for slow path , the helper itself can afford to be slow: it implicitly linearizes , unclones and drops offloads from the skb. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "skb_change_tail",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "skb_change_tail": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn ctx",
          " ctx->len + len_diff",
          " 0"
        ]
      }
    ]
  },
  "startLine": 72,
  "endLine": 76,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_adjust_troom",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " const __s32 len_diff"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "skb_change_tail"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sk_skb",
    "sched_cls",
    "sched_act"
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
ctx_adjust_troom(struct __sk_buff *ctx, const __s32 len_diff)
{
	return skb_change_tail(ctx, ctx->len + len_diff, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 78,
  "endLine": 82,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_full_len",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u64",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused __u64
ctx_full_len(const struct __sk_buff *ctx)
{
	return ctx->len;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 84,
  "endLine": 88,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_wire_len",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused __u32
ctx_wire_len(const struct __sk_buff *ctx)
{
	return ctx->wire_len;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 90,
  "endLine": 94,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_store_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " const __u32 off",
    " __u32 data"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused void
ctx_store_meta(struct __sk_buff *ctx, const __u32 off, __u32 data)
{
	ctx->cb[off] = data;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 96,
  "endLine": 100,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_load_meta",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx",
    " const __u32 off"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused __u32
ctx_load_meta(const struct __sk_buff *ctx, const __u32 off)
{
	return ctx->cb[off];
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 102,
  "endLine": 106,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_get_protocol",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u16",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused __u16
ctx_get_protocol(const struct __sk_buff *ctx)
{
	return (__u16)ctx->protocol;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 108,
  "endLine": 112,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/skb.h",
  "funcName": "ctx_get_ifindex",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __sk_buff *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "raw_tracepoint",
    "lwt_seg6local",
    "cgroup_device",
    "sched_cls",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "flow_dissector",
    "sk_reuseport",
    "lwt_out",
    "perf_event",
    "xdp",
    "raw_tracepoint_writable",
    "sock_ops",
    "tracepoint",
    "cgroup_sysctl",
    "kprobe",
    "cgroup_sock_addr",
    "sk_skb",
    "cgroup_skb",
    "cgroup_sock",
    "socket_filter"
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
static __always_inline __maybe_unused __u32
ctx_get_ifindex(const struct __sk_buff *ctx)
{
	return ctx->ifindex;
}

#endif /* __BPF_CTX_SKB_H_ */
