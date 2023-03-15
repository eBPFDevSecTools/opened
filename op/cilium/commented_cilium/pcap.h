/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_PCAP_H_
#define __LIB_PCAP_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#ifdef ENABLE_CAPTURE
#include "common.h"
#include "time_cache.h"
#include "lb.h"

struct pcap_timeval {
	__u32 tv_sec;
	__u32 tv_usec;
};

struct pcap_timeoff {
	__u64 tv_boot;
};

struct pcap_pkthdr {
	union {
		/* User space needs to perform inline conversion from
		 * boot offset to time of day before writing out to
		 * an external file.
		 */
		struct pcap_timeval ts;
		struct pcap_timeoff to;
	};
	__u32 caplen;
	__u32 len;
};

struct capture_msg {
	/* The hash is reserved and always zero for allowing different
	 * header extensions in future.
	 */
	NOTIFY_COMMON_HDR
	/* The pcap hdr must be the last member so that the placement
	 * inside the perf RB is linear: pcap hdr + packet payload.
	 */
	struct pcap_pkthdr hdr;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 48,
  "endLine": 75,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture",
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
      "start_line": 26,
      "end_line": 29,
      "text": "/* User space needs to perform inline conversion from\n\t\t * boot offset to time of day before writing out to\n\t\t * an external file.\n\t\t */"
    },
    {
      "start_line": 38,
      "end_line": 40,
      "text": "/* The hash is reserved and always zero for allowing different\n\t * header extensions in future.\n\t */"
    },
    {
      "start_line": 42,
      "end_line": 44,
      "text": "/* The pcap hdr must be the last member so that the placement\n\t * inside the perf RB is linear: pcap hdr + packet payload.\n\t */"
    },
    {
      "start_line": 57,
      "end_line": 59,
      "text": "/* rule_id is the demuxer for the target pcap file when there are\n\t * multiple capturing rules present.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const __u8 subtype",
    " const __u16 rule_id",
    " const __u64 tstamp",
    " __u64  __cap_len"
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
    "static __always_inline void cilium_capture (struct  __ctx_buff *ctx, const __u8 subtype, const __u16 rule_id, const __u64 tstamp, __u64  __cap_len)\n",
    "{\n",
    "    __u64 ctx_len = ctx_full_len (ctx);\n",
    "    __u64 cap_len = (!__cap_len || ctx_len < __cap_len) ? ctx_len : __cap_len;\n",
    "    struct capture_msg msg = {\n",
    "        .type = CILIUM_NOTIFY_CAPTURE,\n",
    "        .subtype = subtype,\n",
    "        .source = rule_id,\n",
    "        .hdr = {\n",
    "            .to = {\n",
    "                .tv_boot = tstamp,},\n",
    "            .caplen = cap_len,\n",
    "            .len = ctx_len,},}\n",
    "    ;\n",
    "    ctx_event_output (ctx, &EVENTS_MAP, (cap_len << 32) | BPF_F_CURRENT_CPU, &msg, sizeof (msg));\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_event_output",
    "ctx_full_len"
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
static __always_inline void cilium_capture(struct __ctx_buff *ctx,
					   const __u8 subtype,
					   const __u16 rule_id,
					   const __u64 tstamp,
					   __u64 __cap_len)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = (!__cap_len || ctx_len < __cap_len) ?
			ctx_len : __cap_len;
	/* rule_id is the demuxer for the target pcap file when there are
	 * multiple capturing rules present.
	 */
	struct capture_msg msg = {
		.type    = CILIUM_NOTIFY_CAPTURE,
		.subtype = subtype,
		.source  = rule_id,
		.hdr     = {
			.to	= {
				.tv_boot = tstamp,
			},
			.caplen	= cap_len,
			.len	= ctx_len,
		},
	};

	ctx_event_output(ctx, &EVENTS_MAP, (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 77,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "__cilium_capture_in",
  "developer_inline_comments": [
    {
      "start_line": 4,
      "end_line": 7,
      "text": "/* For later pcap file generation, we export boot time to the RB\n\t * such that user space can later reconstruct a real time of day\n\t * timestamp in-place.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 rule_id",
    " __u32 cap_len"
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
    "static __always_inline void __cilium_capture_in (struct  __ctx_buff *ctx, __u16 rule_id, __u32 cap_len)\n",
    "{\n",
    "    cilium_capture (ctx, CAPTURE_INGRESS, rule_id, bpf_ktime_cache_set (boot_ns), cap_len);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_capture",
    "bpf_ktime_cache_set"
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
static __always_inline void __cilium_capture_in(struct __ctx_buff *ctx,
						__u16 rule_id, __u32 cap_len)
{
	/* For later pcap file generation, we export boot time to the RB
	 * such that user space can later reconstruct a real time of day
	 * timestamp in-place.
	 */
	cilium_capture(ctx, CAPTURE_INGRESS, rule_id,
		       bpf_ktime_cache_set(boot_ns), cap_len);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 88,
  "endLine": 93,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "__cilium_capture_out",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u16 rule_id",
    " __u32 cap_len"
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
    "static __always_inline void __cilium_capture_out (struct  __ctx_buff *ctx, __u16 rule_id, __u32 cap_len)\n",
    "{\n",
    "    cilium_capture (ctx, CAPTURE_EGRESS, rule_id, bpf_ktime_cache_get (), cap_len);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_capture",
    "bpf_ktime_cache_get"
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
static __always_inline void __cilium_capture_out(struct __ctx_buff *ctx,
						 __u16 rule_id, __u32 cap_len)
{
	cilium_capture(ctx, CAPTURE_EGRESS, rule_id,
		       bpf_ktime_cache_get(), cap_len);
}

/* The capture_enabled integer ({0,1}) is enabled/disabled via BPF based ELF
 * templating. Meaning, when disabled, the verifier's dead code elimination
 * will ensure that there is no overhead when the facility is not used. The
 * below is a fallback definition for when the templating var is not defined.
 */
#ifndef capture_enabled
# define capture_enabled (__ctx_is == __ctx_xdp)
#endif /* capture_enabled */

struct capture_cache {
	bool  rule_seen;
	__u16 rule_id;
	__u16 cap_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct capture_cache);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} cilium_capture_cache __section_maps_btf;

struct capture_rule {
	__u16 rule_id;
	__u16 reserved;
	__u32 cap_len;
};

/* 5-tuple wildcard key / mask. */
struct capture4_wcard {
	__be32 saddr;   /* masking: prefix */
	__be32 daddr;   /* masking: prefix */
	__be16 sport;   /* masking: 0 or 0xffff */
	__be16 dport;   /* masking: 0 or 0xffff */
	__u8   nexthdr; /* masking: 0 or 0xff */
	__u8   smask;   /* prefix len: saddr */
	__u8   dmask;   /* prefix len: daddr */
	__u8   flags;   /* reserved: 0 */
};

/* 5-tuple wildcard key / mask. */
struct capture6_wcard {
	union v6addr saddr; /* masking: prefix */
	union v6addr daddr; /* masking: prefix */
	__be16 sport;       /* masking: 0 or 0xffff */
	__be16 dport;       /* masking: 0 or 0xffff */
	__u8   nexthdr;     /* masking: 0 or 0xff */
	__u8   smask;       /* prefix len: saddr */
	__u8   dmask;       /* prefix len: daddr */
	__u8   flags;       /* reserved: 0 */
};

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct capture4_wcard);
	__type(value, struct capture_rule);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CAPTURE4_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CAPTURE4_RULES __section_maps_btf;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 158,
  "endLine": 170,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture4_masked_key",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "/* The capture_enabled integer ({0,1}) is enabled/disabled via BPF based ELF\n * templating. Meaning, when disabled, the verifier's dead code elimination\n * will ensure that there is no overhead when the facility is not used. The\n * below is a fallback definition for when the templating var is not defined.\n */"
    },
    {
      "start_line": 8,
      "end_line": 8,
      "text": "/* capture_enabled */"
    },
    {
      "start_line": 30,
      "end_line": 30,
      "text": "/* 5-tuple wildcard key / mask. */"
    },
    {
      "start_line": 32,
      "end_line": 32,
      "text": "/* masking: prefix */"
    },
    {
      "start_line": 33,
      "end_line": 33,
      "text": "/* masking: prefix */"
    },
    {
      "start_line": 34,
      "end_line": 34,
      "text": "/* masking: 0 or 0xffff */"
    },
    {
      "start_line": 35,
      "end_line": 35,
      "text": "/* masking: 0 or 0xffff */"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "/* masking: 0 or 0xff */"
    },
    {
      "start_line": 37,
      "end_line": 37,
      "text": "/* prefix len: saddr */"
    },
    {
      "start_line": 38,
      "end_line": 38,
      "text": "/* prefix len: daddr */"
    },
    {
      "start_line": 39,
      "end_line": 39,
      "text": "/* reserved: 0 */"
    },
    {
      "start_line": 42,
      "end_line": 42,
      "text": "/* 5-tuple wildcard key / mask. */"
    },
    {
      "start_line": 44,
      "end_line": 44,
      "text": "/* masking: prefix */"
    },
    {
      "start_line": 45,
      "end_line": 45,
      "text": "/* masking: prefix */"
    },
    {
      "start_line": 46,
      "end_line": 46,
      "text": "/* masking: 0 or 0xffff */"
    },
    {
      "start_line": 47,
      "end_line": 47,
      "text": "/* masking: 0 or 0xffff */"
    },
    {
      "start_line": 48,
      "end_line": 48,
      "text": "/* masking: 0 or 0xff */"
    },
    {
      "start_line": 49,
      "end_line": 49,
      "text": "/* prefix len: saddr */"
    },
    {
      "start_line": 50,
      "end_line": 50,
      "text": "/* prefix len: daddr */"
    },
    {
      "start_line": 51,
      "end_line": 51,
      "text": "/* reserved: 0 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct capture4_wcard *orig",
    " const struct capture4_wcard *mask",
    " struct capture4_wcard *out"
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
    "static __always_inline void cilium_capture4_masked_key (const struct capture4_wcard *orig, const struct capture4_wcard *mask, struct capture4_wcard *out)\n",
    "{\n",
    "    out->daddr = orig->daddr & mask->daddr;\n",
    "    out->saddr = orig->saddr & mask->saddr;\n",
    "    out->dport = orig->dport & mask->dport;\n",
    "    out->sport = orig->sport & mask->sport;\n",
    "    out->nexthdr = orig->nexthdr & mask->nexthdr;\n",
    "    out->dmask = mask->dmask;\n",
    "    out->smask = mask->smask;\n",
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
cilium_capture4_masked_key(const struct capture4_wcard *orig,
			   const struct capture4_wcard *mask,
			   struct capture4_wcard *out)
{
	out->daddr = orig->daddr & mask->daddr;
	out->saddr = orig->saddr & mask->saddr;
	out->dport = orig->dport & mask->dport;
	out->sport = orig->sport & mask->sport;
	out->nexthdr = orig->nexthdr & mask->nexthdr;
	out->dmask = mask->dmask;
	out->smask = mask->smask;
}

/* The agent is generating and emitting the PREFIX_MASKS4 and regenerating
 * if a mask was added or removed. The cilium_capture4_rules can have n
 * entries with m different PREFIX_MASKS4 where n >> m. Lookup performance
 * depends mainly on m. Below is a fallback / example definition mainly for
 * compile testing given agent typically emits this instead. Ordering of
 * masks from agent side can f.e. be based on # of 1s from high to low.
 */
#ifndef PREFIX_MASKS4
# define PREFIX_MASKS4					\
	{						\
		/* rule_id 1:				\
		 *  srcIP/32, dstIP/32, dport, nexthdr	\
		 */					\
		.daddr   = 0xffffffff,			\
		.dmask   = 32,				\
		.saddr   = 0xffffffff,			\
		.smask   = 32,				\
		.dport   = 0xffff,			\
		.sport   = 0,				\
		.nexthdr = 0xff,			\
	}, {						\
		/* rule_id 2 (1st mask):		\
		 *  srcIP/32 or dstIP/32		\
		 */					\
		.daddr   = 0xffffffff,			\
		.dmask   = 32,				\
		.saddr   = 0,				\
		.smask   = 0,				\
		.dport   = 0,				\
		.sport   = 0,				\
		.nexthdr = 0,				\
	}, {						\
		/* rule_id 2 (2nd mask):		\
		 *  srcIP/32 or dstIP/32		\
		 */					\
		.daddr   = 0,				\
		.dmask   = 0,				\
		.saddr   = 0xffffffff,			\
		.smask   = 32,				\
		.dport   = 0,				\
		.sport   = 0,				\
		.nexthdr = 0,				\
	},
#endif /* PREFIX_MASKS4 */

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
  "startLine": 217,
  "endLine": 257,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture4_classify_wcard",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 7,
      "text": "/* The agent is generating and emitting the PREFIX_MASKS4 and regenerating\n * if a mask was added or removed. The cilium_capture4_rules can have n\n * entries with m different PREFIX_MASKS4 where n >> m. Lookup performance\n * depends mainly on m. Below is a fallback / example definition mainly for\n * compile testing given agent typically emits this instead. Ordering of\n * masks from agent side can f.e. be based on # of 1s from high to low.\n */"
    },
    {
      "start_line": 11,
      "end_line": 13,
      "text": "/* rule_id 1:\t\t\t\t\\\n\t\t *  srcIP/32, dstIP/32, dport, nexthdr\t\\\n\t\t */"
    },
    {
      "start_line": 22,
      "end_line": 24,
      "text": "/* rule_id 2 (1st mask):\t\t\\\n\t\t *  srcIP/32 or dstIP/32\t\t\\\n\t\t */"
    },
    {
      "start_line": 33,
      "end_line": 35,
      "text": "/* rule_id 2 (2nd mask):\t\t\\\n\t\t *  srcIP/32 or dstIP/32\t\t\\\n\t\t */"
    },
    {
      "start_line": 44,
      "end_line": 44,
      "text": "/* PREFIX_MASKS4 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  CAPTURE4_RULES"
  ],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinestructcapture_rule",
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
    "static __always_inline struct capture_rule *cilium_capture4_classify_wcard (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct capture4_wcard prefix_masks [] = {PREFIX_MASKS4};\n",
    "    struct capture4_wcard okey, lkey;\n",
    "    struct capture_rule *match;\n",
    "    void *data, *data_end;\n",
    "    struct iphdr *ip4;\n",
    "    int i;\n",
    "    const int size = sizeof (prefix_masks) / sizeof (prefix_masks [0]);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip4))\n",
    "        return NULL;\n",
    "    okey.daddr = ip4->daddr;\n",
    "    okey.dmask = 32;\n",
    "    okey.saddr = ip4->saddr;\n",
    "    okey.smask = 32;\n",
    "    okey.nexthdr = ip4->protocol;\n",
    "    if (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP)\n",
    "        return NULL;\n",
    "    if (ctx_load_bytes (ctx, ETH_HLEN + ipv4_hdrlen (ip4), &okey.sport, 4) < 0)\n",
    "        return NULL;\n",
    "    okey.flags = 0;\n",
    "    lkey.flags = 0;\n",
    "    _Pragma (\"unroll\")\n",
    "    for (i = 0; i < size; i++) {\n",
    "        cilium_capture4_masked_key (&okey, &prefix_masks[i], &lkey);\n",
    "        match = map_lookup_elem (& CAPTURE4_RULES, & lkey);\n",
    "        if (match)\n",
    "            return match;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_hdrlen",
    "cilium_capture4_masked_key",
    "_Pragma",
    "revalidate_data",
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
static __always_inline struct capture_rule *
cilium_capture4_classify_wcard(struct __ctx_buff *ctx)
{
	struct capture4_wcard prefix_masks[] = { PREFIX_MASKS4 };
	struct capture4_wcard okey, lkey;
	struct capture_rule *match;
	void *data, *data_end;
	struct iphdr *ip4;
	int i;
	const int size = sizeof(prefix_masks) /
			 sizeof(prefix_masks[0]);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return NULL;

	okey.daddr = ip4->daddr;
	okey.dmask = 32;
	okey.saddr = ip4->saddr;
	okey.smask = 32;
	okey.nexthdr = ip4->protocol;

	if (ip4->protocol != IPPROTO_TCP &&
	    ip4->protocol != IPPROTO_UDP)
		return NULL;
	if (ctx_load_bytes(ctx, ETH_HLEN + ipv4_hdrlen(ip4),
			   &okey.sport, 4) < 0)
		return NULL;

	okey.flags = 0;
	lkey.flags = 0;

_Pragma("unroll")
	for (i = 0; i < size; i++) {
		cilium_capture4_masked_key(&okey, &prefix_masks[i], &lkey);
		match = map_lookup_elem(&CAPTURE4_RULES, &lkey);
		if (match)
			return match;
	}

	return NULL;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct capture6_wcard);
	__type(value, struct capture_rule);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CAPTURE6_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} CAPTURE6_RULES __section_maps_btf;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 270,
  "endLine": 284,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture6_masked_key",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct capture6_wcard *orig",
    " const struct capture6_wcard *mask",
    " struct capture6_wcard *out"
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
    "static __always_inline void cilium_capture6_masked_key (const struct capture6_wcard *orig, const struct capture6_wcard *mask, struct capture6_wcard *out)\n",
    "{\n",
    "    out->daddr.d1 = orig->daddr.d1 & mask->daddr.d1;\n",
    "    out->daddr.d2 = orig->daddr.d2 & mask->daddr.d2;\n",
    "    out->saddr.d1 = orig->saddr.d1 & mask->saddr.d1;\n",
    "    out->saddr.d2 = orig->saddr.d2 & mask->saddr.d2;\n",
    "    out->dport = orig->dport & mask->dport;\n",
    "    out->sport = orig->sport & mask->sport;\n",
    "    out->nexthdr = orig->nexthdr & mask->nexthdr;\n",
    "    out->dmask = mask->dmask;\n",
    "    out->smask = mask->smask;\n",
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
cilium_capture6_masked_key(const struct capture6_wcard *orig,
			   const struct capture6_wcard *mask,
			   struct capture6_wcard *out)
{
	out->daddr.d1 = orig->daddr.d1 & mask->daddr.d1;
	out->daddr.d2 = orig->daddr.d2 & mask->daddr.d2;
	out->saddr.d1 = orig->saddr.d1 & mask->saddr.d1;
	out->saddr.d2 = orig->saddr.d2 & mask->saddr.d2;
	out->dport = orig->dport & mask->dport;
	out->sport = orig->sport & mask->sport;
	out->nexthdr = orig->nexthdr & mask->nexthdr;
	out->dmask = mask->dmask;
	out->smask = mask->smask;
}

/* The agent is generating and emitting the PREFIX_MASKS6 and regenerating
 * if a mask was added or removed. Example for compile testing:
 */
#ifndef PREFIX_MASKS6
# define PREFIX_MASKS6					 \
	{						 \
		/* rule_id 1:				 \
		 *  srcIP/128, dstIP/128, dport, nexthdr \
		 */					 \
		.daddr = {				 \
			.d1 = 0xffffffff,		 \
			.d2 = 0xffffffff,		 \
		},					 \
		.dmask    = 128,			 \
		.saddr = {				 \
			.d1 = 0xffffffff,		 \
			.d2 = 0xffffffff,		 \
		},					 \
		.smask    = 128,			 \
		.dport    = 0xffff,			 \
		.sport    = 0,				 \
		.nexthdr  = 0xff,			 \
	}, {						 \
		/* rule_id 2 (1st mask):		 \
		 *  srcIP/128 or dstIP/128		 \
		 */					 \
		.daddr = {				 \
			.d1 = 0xffffffff,		 \
			.d2 = 0xffffffff,		 \
		},					 \
		.dmask    = 128,			 \
		.saddr    = {},				 \
		.smask    = 0,				 \
		.dport    = 0,				 \
		.sport    = 0,				 \
		.nexthdr  = 0,				 \
	}, {						 \
		/* rule_id 2 (2nd mask):		 \
		 *  srcIP/128 or dstIP/128		 \
		 */					 \
		.daddr    = {},				 \
		.dmask    = 0,				 \
		.saddr = {				 \
			.d1 = 0xffffffff,		 \
			.d2 = 0xffffffff,		 \
		},					 \
		.smask    = 128,			 \
		.dport    = 0,				 \
		.sport    = 0,				 \
		.nexthdr  = 0,				 \
	},
#endif /* PREFIX_MASKS6 */

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
  "startLine": 339,
  "endLine": 382,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture6_classify_wcard",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 3,
      "text": "/* The agent is generating and emitting the PREFIX_MASKS6 and regenerating\n * if a mask was added or removed. Example for compile testing:\n */"
    },
    {
      "start_line": 7,
      "end_line": 9,
      "text": "/* rule_id 1:\t\t\t\t \\\n\t\t *  srcIP/128, dstIP/128, dport, nexthdr \\\n\t\t */"
    },
    {
      "start_line": 24,
      "end_line": 26,
      "text": "/* rule_id 2 (1st mask):\t\t \\\n\t\t *  srcIP/128 or dstIP/128\t\t \\\n\t\t */"
    },
    {
      "start_line": 38,
      "end_line": 40,
      "text": "/* rule_id 2 (2nd mask):\t\t \\\n\t\t *  srcIP/128 or dstIP/128\t\t \\\n\t\t */"
    },
    {
      "start_line": 52,
      "end_line": 52,
      "text": "/* PREFIX_MASKS6 */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  CAPTURE6_RULES"
  ],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinestructcapture_rule",
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
    "static __always_inline struct capture_rule *cilium_capture6_classify_wcard (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct capture6_wcard prefix_masks [] = {PREFIX_MASKS6};\n",
    "    struct capture6_wcard okey, lkey;\n",
    "    struct capture_rule *match;\n",
    "    void *data, *data_end;\n",
    "    struct ipv6hdr *ip6;\n",
    "    int i, ret, l3_off = ETH_HLEN;\n",
    "    const int size = sizeof (prefix_masks) / sizeof (prefix_masks [0]);\n",
    "    if (!revalidate_data (ctx, &data, &data_end, &ip6))\n",
    "        return NULL;\n",
    "    ipv6_addr_copy (&okey.daddr, (union v6addr *) &ip6->daddr);\n",
    "    okey.dmask = 128;\n",
    "    ipv6_addr_copy (&okey.saddr, (union v6addr *) &ip6->saddr);\n",
    "    okey.smask = 128;\n",
    "    okey.nexthdr = ip6->nexthdr;\n",
    "    ret = ipv6_hdrlen (ctx, & okey.nexthdr);\n",
    "    if (ret < 0)\n",
    "        return NULL;\n",
    "    if (okey.nexthdr != IPPROTO_TCP && okey.nexthdr != IPPROTO_UDP)\n",
    "        return NULL;\n",
    "    if (ctx_load_bytes (ctx, l3_off + ret, &okey.sport, 4) < 0)\n",
    "        return NULL;\n",
    "    okey.flags = 0;\n",
    "    lkey.flags = 0;\n",
    "    _Pragma (\"unroll\")\n",
    "    for (i = 0; i < size; i++) {\n",
    "        cilium_capture6_masked_key (&okey, &prefix_masks[i], &lkey);\n",
    "        match = map_lookup_elem (& CAPTURE6_RULES, & lkey);\n",
    "        if (match)\n",
    "            return match;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "_Pragma",
    "revalidate_data",
    "cilium_capture6_masked_key",
    "ctx_load_bytes",
    "ipv6_hdrlen",
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
static __always_inline struct capture_rule *
cilium_capture6_classify_wcard(struct __ctx_buff *ctx)
{
	struct capture6_wcard prefix_masks[] = { PREFIX_MASKS6 };
	struct capture6_wcard okey, lkey;
	struct capture_rule *match;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int i, ret, l3_off = ETH_HLEN;
	const int size = sizeof(prefix_masks) /
			 sizeof(prefix_masks[0]);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return NULL;

	ipv6_addr_copy(&okey.daddr, (union v6addr *)&ip6->daddr);
	okey.dmask = 128;
	ipv6_addr_copy(&okey.saddr, (union v6addr *)&ip6->saddr);
	okey.smask = 128;
	okey.nexthdr = ip6->nexthdr;

	ret = ipv6_hdrlen(ctx, &okey.nexthdr);
	if (ret < 0)
		return NULL;
	if (okey.nexthdr != IPPROTO_TCP &&
	    okey.nexthdr != IPPROTO_UDP)
		return NULL;
	if (ctx_load_bytes(ctx, l3_off + ret,
			   &okey.sport, 4) < 0)
		return NULL;

	okey.flags = 0;
	lkey.flags = 0;

_Pragma("unroll")
	for (i = 0; i < size; i++) {
		cilium_capture6_masked_key(&okey, &prefix_masks[i], &lkey);
		match = map_lookup_elem(&CAPTURE6_RULES, &lkey);
		if (match)
			return match;
	}

	return NULL;
}
#endif /* ENABLE_IPV6 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 385,
  "endLine": 408,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_classify_wcard",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinestructcapture_rule",
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
    "static __always_inline struct capture_rule *cilium_capture_classify_wcard (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    struct capture_rule *ret = NULL;\n",
    "    __u16 proto;\n",
    "    if (!validate_ethertype (ctx, &proto))\n",
    "        return ret;\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ret = cilium_capture4_classify_wcard (ctx);\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ret = cilium_capture6_classify_wcard (ctx);\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_capture4_classify_wcard",
    "bpf_htons",
    "validate_ethertype",
    "cilium_capture6_classify_wcard"
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
static __always_inline struct capture_rule *
cilium_capture_classify_wcard(struct __ctx_buff *ctx)
{
	struct capture_rule *ret = NULL;
	__u16 proto;

	if (!validate_ethertype(ctx, &proto))
		return ret;
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		ret = cilium_capture4_classify_wcard(ctx);
		break;
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		ret = cilium_capture6_classify_wcard(ctx);
		break;
#endif
	default:
		break;
	}
	return ret;
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
  "startLine": 410,
  "endLine": 432,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_candidate",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  cilium_capture_cache"
  ],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u16 * rule_id __maybe_unused",
    " __u16 * cap_len __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool cilium_capture_candidate (struct  __ctx_buff * ctx __maybe_unused, __u16 * rule_id __maybe_unused, __u16 * cap_len __maybe_unused)\n",
    "{\n",
    "    if (capture_enabled) {\n",
    "        struct capture_cache *c;\n",
    "        struct capture_rule *r;\n",
    "        __u32 zero = 0;\n",
    "        c = map_lookup_elem (& cilium_capture_cache, & zero);\n",
    "        if (always_succeeds (c)) {\n",
    "            r = cilium_capture_classify_wcard (ctx);\n",
    "            c->rule_seen = r;\n",
    "            if (r) {\n",
    "                c->cap_len = *cap_len = (__u16) r->cap_len;\n",
    "                c->rule_id = *rule_id = r->rule_id;\n",
    "                return true;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return false;\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_capture_classify_wcard",
    "always_succeeds"
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
cilium_capture_candidate(struct __ctx_buff *ctx __maybe_unused,
			 __u16 *rule_id __maybe_unused,
			 __u16 *cap_len __maybe_unused)
{
	if (capture_enabled) {
		struct capture_cache *c;
		struct capture_rule *r;
		__u32 zero = 0;

		c = map_lookup_elem(&cilium_capture_cache, &zero);
		if (always_succeeds(c)) {
			r = cilium_capture_classify_wcard(ctx);
			c->rule_seen = r;
			if (r) {
				c->cap_len = *cap_len = (__u16)r->cap_len;
				c->rule_id = *rule_id = r->rule_id;
				return true;
			}
		}
	}
	return false;
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
  "startLine": 434,
  "endLine": 455,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_cached",
  "developer_inline_comments": [
    {
      "start_line": 10,
      "end_line": 13,
      "text": "/* Avoid full classification a 2nd time due to i) overhead but\n\t\t * also since ii) we might have pushed an encap header in front\n\t\t * where we don't want to dissect everything again.\n\t\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  cilium_capture_cache"
  ],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u16 * rule_id __maybe_unused",
    " __u32 * cap_len __maybe_unused"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool cilium_capture_cached (struct  __ctx_buff * ctx __maybe_unused, __u16 * rule_id __maybe_unused, __u32 * cap_len __maybe_unused)\n",
    "{\n",
    "    if (capture_enabled) {\n",
    "        struct capture_cache *c;\n",
    "        __u32 zero = 0;\n",
    "        c = map_lookup_elem (& cilium_capture_cache, & zero);\n",
    "        if (always_succeeds (c) && c->rule_seen) {\n",
    "            *cap_len = c->cap_len;\n",
    "            *rule_id = c->rule_id;\n",
    "            return true;\n",
    "        }\n",
    "    }\n",
    "    return false;\n",
    "}\n"
  ],
  "called_function_list": [
    "always_succeeds"
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
cilium_capture_cached(struct __ctx_buff *ctx __maybe_unused,
		      __u16 *rule_id __maybe_unused,
		      __u32 *cap_len __maybe_unused)
{
	if (capture_enabled) {
		struct capture_cache *c;
		__u32 zero = 0;

		/* Avoid full classification a 2nd time due to i) overhead but
		 * also since ii) we might have pushed an encap header in front
		 * where we don't want to dissect everything again.
		 */
		c = map_lookup_elem(&cilium_capture_cache, &zero);
		if (always_succeeds(c) && c->rule_seen) {
			*cap_len = c->cap_len;
			*rule_id = c->rule_id;
			return true;
		}
	}
	return false;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 457,
  "endLine": 465,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_in",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline void cilium_capture_in (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    __u16 cap_len;\n",
    "    __u16 rule_id;\n",
    "    if (cilium_capture_candidate (ctx, &rule_id, &cap_len))\n",
    "        __cilium_capture_in (ctx, rule_id, cap_len);\n",
    "}\n"
  ],
  "called_function_list": [
    "__cilium_capture_in",
    "cilium_capture_candidate"
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
cilium_capture_in(struct __ctx_buff *ctx __maybe_unused)
{
	__u16 cap_len;
	__u16 rule_id;

	if (cilium_capture_candidate(ctx, &rule_id, &cap_len))
		__cilium_capture_in(ctx, rule_id, cap_len);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 467,
  "endLine": 479,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_out",
  "developer_inline_comments": [
    {
      "start_line": 7,
      "end_line": 10,
      "text": "/* cilium_capture_out() is always paired with cilium_capture_in(), so\n\t * we can rely on previous cached result on whether to push the pkt\n\t * to the RB or not.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline void cilium_capture_out (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "    __u32 cap_len;\n",
    "    __u16 rule_id;\n",
    "    if (cilium_capture_cached (ctx, &rule_id, &cap_len))\n",
    "        __cilium_capture_out (ctx, rule_id, cap_len);\n",
    "}\n"
  ],
  "called_function_list": [
    "__cilium_capture_out",
    "cilium_capture_cached"
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
cilium_capture_out(struct __ctx_buff *ctx __maybe_unused)
{
	__u32 cap_len;
	__u16 rule_id;

	/* cilium_capture_out() is always paired with cilium_capture_in(), so
	 * we can rely on previous cached result on whether to push the pkt
	 * to the RB or not.
	 */
	if (cilium_capture_cached(ctx, &rule_id, &cap_len))
		__cilium_capture_out(ctx, rule_id, cap_len);
}

#else /* ENABLE_CAPTURE */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 483,
  "endLine": 486,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_in",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* ENABLE_CAPTURE */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline void cilium_capture_in (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "__cilium_capture_in",
    "cilium_capture_candidate"
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
cilium_capture_in(struct __ctx_buff *ctx __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 488,
  "endLine": 491,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/pcap.h",
  "funcName": "cilium_capture_out",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused"
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
    "static __always_inline void cilium_capture_out (struct  __ctx_buff * ctx __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "__cilium_capture_out",
    "cilium_capture_cached"
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
cilium_capture_out(struct __ctx_buff *ctx __maybe_unused)
{
}

#endif /* ENABLE_CAPTURE */
#endif /* __LIB_PCAP_H_ */
