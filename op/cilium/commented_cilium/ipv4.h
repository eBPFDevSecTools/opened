/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IPV4__
#define __LIB_IPV4__

#include <linux/ip.h>

#include "dbg.h"
#include "metrics.h"

struct ipv4_frag_id {
	__be32	daddr;
	__be32	saddr;
	__be16	id;		/* L4 datagram identifier */
	__u8	proto;
	__u8	pad;
} __packed;

struct ipv4_frag_l4ports {
	__be16	sport;
	__be16	dport;
} __packed;

#ifdef ENABLE_IPV4_FRAGMENTS
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_frag_id);
	__type(value, struct ipv4_frag_l4ports);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES);
} IPV4_FRAG_DATAGRAMS_MAP __section_maps_btf;
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 35,
  "endLine": 39,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_load_daddr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int off",
    " __u32 *dst"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv4_load_daddr (struct  __ctx_buff *ctx, int off, __u32 *dst)\n",
    "{\n",
    "    return ctx_load_bytes (ctx, off + offsetof (struct iphdr, daddr), dst, 4);\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_load_bytes",
    "offsetof"
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
static __always_inline int ipv4_load_daddr(struct __ctx_buff *ctx, int off,
					   __u32 *dst)
{
	return ctx_load_bytes(ctx, off + offsetof(struct iphdr, daddr), dst, 4);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 41,
  "endLine": 55,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_dec_ttl",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " int off",
    " const struct iphdr *ip4"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "l3_csum_replace"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline int ipv4_dec_ttl (struct  __ctx_buff *ctx, int off, const struct iphdr *ip4)\n",
    "{\n",
    "    __u8 new_ttl, ttl = ip4->ttl;\n",
    "    if (ttl <= 1)\n",
    "        return 1;\n",
    "    new_ttl = ttl - 1;\n",
    "    l3_csum_replace (ctx, off + offsetof (struct iphdr, check), ttl, new_ttl, 2);\n",
    "    ctx_store_bytes (ctx, off + offsetof (struct iphdr, ttl), &new_ttl, sizeof (new_ttl), 0);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
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
static __always_inline int ipv4_dec_ttl(struct __ctx_buff *ctx, int off,
					const struct iphdr *ip4)
{
	__u8 new_ttl, ttl = ip4->ttl;

	if (ttl <= 1)
		return 1;

	new_ttl = ttl - 1;
	/* l3_csum_replace() takes at min 2 bytes, zero extended. */
	l3_csum_replace(ctx, off + offsetof(struct iphdr, check), ttl, new_ttl, 2);
	ctx_store_bytes(ctx, off + offsetof(struct iphdr, ttl), &new_ttl, sizeof(new_ttl), 0);

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 60,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_hdrlen",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr *ip4"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv4_hdrlen (const struct iphdr *ip4)\n",
    "{\n",
    "    return ip4->ihl * 4;\n",
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
static __always_inline int ipv4_hdrlen(const struct iphdr *ip4)
{
	return ip4->ihl * 4;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 62,
  "endLine": 74,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_is_fragment",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr *ip4"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline bool ipv4_is_fragment (const struct iphdr *ip4)\n",
    "{\n",
    "    return ip4->frag_off & bpf_htons (0x3FFF);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __always_inline bool ipv4_is_fragment(const struct iphdr *ip4)
{
	/* The frag_off portion of the header consists of:
	 *
	 * +----+----+----+----------------------------------+
	 * | RS | DF | MF | ...13 bits of fragment offset... |
	 * +----+----+----+----------------------------------+
	 *
	 * If "More fragments" or the offset is nonzero, then this is an IP
	 * fragment (RFC791).
	 */
	return ip4->frag_off & bpf_htons(0x3FFF);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 76,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_is_not_first_fragment",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr *ip4"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline bool ipv4_is_not_first_fragment (const struct iphdr *ip4)\n",
    "{\n",
    "    return ip4->frag_off & bpf_htons (0x1FFF);\n",
    "}\n"
  ],
  "called_function_list": [
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
static __always_inline bool ipv4_is_not_first_fragment(const struct iphdr *ip4)
{
	/* Ignore "More fragments" bit to catch all fragments but the first */
	return ip4->frag_off & bpf_htons(0x1FFF);
}

/* Simply a reverse of ipv4_is_not_first_fragment to avoid double negative. */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_has_l4_header",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct iphdr *ip4"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline bool ipv4_has_l4_header (const struct iphdr *ip4)\n",
    "{\n",
    "    return !ipv4_is_not_first_fragment (ip4);\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_is_not_first_fragment"
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
static __always_inline bool ipv4_has_l4_header(const struct iphdr *ip4)
{
	return !ipv4_is_not_first_fragment(ip4);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 88,
  "endLine": 92,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_is_in_subnet",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__be32 addr",
    " __be32 subnet",
    " int prefixlen"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline bool ipv4_is_in_subnet (__be32 addr, __be32 subnet, int prefixlen)\n",
    "{\n",
    "    return (addr & bpf_htonl (~((1 << (32 - prefixlen)) - 1))) == subnet;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_htonl"
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
static __always_inline bool ipv4_is_in_subnet(__be32 addr,
					      __be32 subnet, int prefixlen)
{
	return (addr & bpf_htonl(~((1 << (32 - prefixlen)) - 1))) == subnet;
}

#ifdef ENABLE_IPV4_FRAGMENTS
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
  "startLine": 95,
  "endLine": 108,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_frag_get_l4ports",
  "updateMaps": [],
  "readMaps": [
    "  IPV4_FRAG_DATAGRAMS_MAP"
  ],
  "input": [
    "const struct ipv4_frag_id *frag_id",
    " struct ipv4_frag_l4ports *ports"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv4_frag_get_l4ports (const struct ipv4_frag_id *frag_id, struct ipv4_frag_l4ports *ports)\n",
    "{\n",
    "    struct ipv4_frag_l4ports *tmp;\n",
    "    tmp = map_lookup_elem (& IPV4_FRAG_DATAGRAMS_MAP, frag_id);\n",
    "    if (!tmp)\n",
    "        return DROP_FRAG_NOT_FOUND;\n",
    "    memcpy (ports, tmp, sizeof (*ports));\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy"
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
ipv4_frag_get_l4ports(const struct ipv4_frag_id *frag_id,
		      struct ipv4_frag_l4ports *ports)
{
	struct ipv4_frag_l4ports *tmp;

	tmp = map_lookup_elem(&IPV4_FRAG_DATAGRAMS_MAP, frag_id);
	if (!tmp)
		return DROP_FRAG_NOT_FOUND;

	/* Do not make ports a pointer to map data, copy from map */
	memcpy(ports, tmp, sizeof(*ports));
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 110,
  "endLine": 161,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/ipv4.h",
  "funcName": "ipv4_handle_fragmentation",
  "updateMaps": [
    " IPV4_FRAG_DATAGRAMS_MAP"
  ],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " const struct iphdr *ip4",
    " int l4_off",
    " enum ct_dir ct_dir",
    " struct ipv4_frag_l4ports *ports",
    " bool *has_l4_header"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sched_cls",
    "perf_event",
    "sched_act",
    "cgroup_sock",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint_writable",
    "xdp",
    "sk_reuseport",
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "kprobe",
    "socket_filter",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv4_handle_fragmentation (struct  __ctx_buff *ctx, const struct iphdr *ip4, int l4_off, enum ct_dir ct_dir, struct ipv4_frag_l4ports *ports, bool *has_l4_header)\n",
    "{\n",
    "    bool is_fragment, not_first_fragment;\n",
    "    enum metric_dir dir;\n",
    "    int ret;\n",
    "    struct ipv4_frag_id frag_id = {\n",
    "        .daddr = ip4->daddr,\n",
    "        .saddr = ip4->saddr,\n",
    "        .id = ip4->id,\n",
    "        .proto = ip4->protocol,\n",
    "        .pad = 0,}\n",
    "    ;\n",
    "    is_fragment = ipv4_is_fragment (ip4);\n",
    "    dir = ct_to_metrics_dir (ct_dir);\n",
    "    if (unlikely (is_fragment)) {\n",
    "        update_metrics (ctx_full_len (ctx), dir, REASON_FRAG_PACKET);\n",
    "        not_first_fragment = ipv4_is_not_first_fragment (ip4);\n",
    "        if (has_l4_header)\n",
    "            *has_l4_header = !not_first_fragment;\n",
    "        if (likely (not_first_fragment))\n",
    "            return ipv4_frag_get_l4ports (&frag_id, ports);\n",
    "    }\n",
    "    ret = ctx_load_bytes (ctx, l4_off, ports, 4);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    if (unlikely (is_fragment)) {\n",
    "        if (map_update_elem (&IPV4_FRAG_DATAGRAMS_MAP, &frag_id, ports, BPF_ANY))\n",
    "            update_metrics (ctx_full_len (ctx), dir, REASON_FRAG_PACKET_UPDATE);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "likely",
    "unlikely",
    "ct_to_metrics_dir",
    "ctx_full_len",
    "ctx_load_bytes",
    "ipv4_is_fragment",
    "ipv4_is_not_first_fragment",
    "update_metrics",
    "ipv4_frag_get_l4ports"
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
ipv4_handle_fragmentation(struct __ctx_buff *ctx,
			  const struct iphdr *ip4, int l4_off,
			  enum ct_dir ct_dir,
			  struct ipv4_frag_l4ports *ports,
			  bool *has_l4_header)
{
	bool is_fragment, not_first_fragment;
	enum metric_dir dir;
	int ret;

	struct ipv4_frag_id frag_id = {
		.daddr = ip4->daddr,
		.saddr = ip4->saddr,
		.id = ip4->id,
		.proto = ip4->protocol,
		.pad = 0,
	};

	is_fragment = ipv4_is_fragment(ip4);
	dir = ct_to_metrics_dir(ct_dir);

	if (unlikely(is_fragment)) {
		update_metrics(ctx_full_len(ctx), dir, REASON_FRAG_PACKET);

		not_first_fragment = ipv4_is_not_first_fragment(ip4);
		if (has_l4_header)
			*has_l4_header = !not_first_fragment;

		if (likely(not_first_fragment))
			return ipv4_frag_get_l4ports(&frag_id, ports);
	}

	/* load sport + dport into tuple */
	ret = ctx_load_bytes(ctx, l4_off, ports, 4);
	if (ret < 0)
		return ret;

	if (unlikely(is_fragment)) {
		/* First logical fragment for this datagram (not necessarily the first
		 * we receive). Fragment has L4 header, create an entry in datagrams map.
		 */
		if (map_update_elem(&IPV4_FRAG_DATAGRAMS_MAP, &frag_id, ports, BPF_ANY))
			update_metrics(ctx_full_len(ctx), dir, REASON_FRAG_PACKET_UPDATE);

		/* Do not return an error if map update failed, as nothing prevents us
		 * to process the current packet normally.
		 */
	}

	return 0;
}
#endif

#endif /* __LIB_IPV4__ */
