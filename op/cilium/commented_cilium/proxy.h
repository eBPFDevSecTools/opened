/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_PROXY_H_
#define __LIB_PROXY_H_

#include "conntrack.h"

#if !(__ctx_is == __ctx_skb)
#error "Proxy redirection is only supported from skb context"
#endif

#ifdef ENABLE_TPROXY
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "struct sock*",
          "Description": "Look for TCP socket matching <[ tuple ]>(IP: 1) , optionally in a child network namespace netns. The return value must be checked , and if non-NULL , released via sk_release(). This function is identical to sk_lookup_tcp() , except that it also returns timewait or request sockets. Use sk_fullsock() or tcp_sock() to access the full structure. This helper is available only if the kernel was compiled with CONFIG_NET configuration option. ",
          "Return": " Pointer  to  struct  sock, or NULL in case of failure.  For sockets with                     reuseport option, the struct  sock result is  from  reuse->socks[]  using                     the hash of the tuple.",
          "Function Name": "skc_lookup_tcp",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct sock_tuple ,Var: *tuple}",
            "{Type:  u32 ,Var: tuple_size}",
            "{Type:  u64 ,Var: netns}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "skc_lookup_tcp": [
      {
        "opVar": "\tsk ",
        "inpVar": [
          " ctx",
          " tuple",
          " len",
          " BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_release": [
      {
        "opVar": "NA",
        "inpVar": [
          "release:\tsk"
        ]
      }
    ]
  },
  "startLine": 14,
  "endLine": 42,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "assign_socket_tcp",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct bpf_sock_tuple *tuple",
    " __u32 len",
    " bool established"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "sk_release",
    "skc_lookup_tcp"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "cgroup_sock_addr",
    "xdp",
    "sk_skb",
    "sched_cls"
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
static __always_inline int
assign_socket_tcp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len, bool established)
{
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk;
	__u32 dbg_ctx;

	sk = skc_lookup_tcp(ctx, tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		goto out;

	if (established && sk->state == BPF_TCP_TIME_WAIT)
		goto release;
	if (established && sk->state == BPF_TCP_LISTEN)
		goto release;

	dbg_ctx = sk->family << 16 | ctx->protocol;
	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, dbg_ctx);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
release:
	sk_release(sk);
out:
	return result;
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
          "Return Type": "struct sock*",
          "Description": "Look for UDP socket matching <[ tuple ]>(IP: 1) , optionally in a child network namespace netns. The return value must be checked , and if non-NULL , released via sk_release(). The <[ ctx ]>(IP: 0) should point to the context of the program , such as the skb or socket (depending on the hook in use). This is used to determine the base network namespace for the lookup. <[ tuple_size ]>(IP: 2) must be one of: sizeof(tuple->ipv4) Look for an IPv4 socket. sizeof(tuple->ipv6) Look for an IPv6 socket. If the <[ netns ]>(IP: 3) is a negative signed 32-bit integer , then the socket lookup table in the <[ netns ]>(IP: 3) associated with the <[ ctx ]>(IP: 0) will will be used. For the TC hooks , this is the <[ netns ]>(IP: 3) of the device in the skb. For socket hooks , this is the <[ netns ]>(IP: 3) of the socket. If <[ netns ]>(IP: 3) is any other signed 32-bit value greater than or equal to zero then it specifies the ID of the <[ netns ]>(IP: 3) relative to the <[ netns ]>(IP: 3) associated with the ctx. <[ netns ]>(IP: 3) values beyond the range of 32-bit integers are reserved for future use. All values for <[ flags ]>(IP: 4) are reserved for future usage , and must be left at zero. This helper is available only if the kernel was compiled with CONFIG_NET configuration option. ",
          "Return": " Pointer  to  struct  sock, or NULL in case of failure.  For sockets with                     reuseport option, the struct  sock result is  from  reuse->socks[]  using                     the hash of the tuple.",
          "Function Name": "sk_lookup_udp",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct sock_tuple ,Var: *tuple}",
            "{Type:  u32 ,Var: tuple_size}",
            "{Type:  u64 ,Var: netns}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "sk_lookup_udp": [
      {
        "opVar": "\tsk ",
        "inpVar": [
          " ctx",
          " tuple",
          " len",
          " BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_release": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tsk"
        ]
      }
    ]
  },
  "startLine": 44,
  "endLine": 67,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "assign_socket_udp",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct bpf_sock_tuple *tuple",
    " __u32 len",
    " bool established __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "sk_release",
    "sk_lookup_udp"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "cgroup_sock_addr",
    "xdp",
    "sk_skb",
    "sched_cls"
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
static __always_inline int
assign_socket_udp(struct __ctx_buff *ctx,
		  struct bpf_sock_tuple *tuple, __u32 len,
		  bool established __maybe_unused)
{
	int result = DROP_PROXY_LOOKUP_FAILED;
	struct bpf_sock *sk;
	__u32 dbg_ctx;

	sk = sk_lookup_udp(ctx, tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		goto out;

	dbg_ctx = sk->family << 16 | ctx->protocol;
	result = sk_assign(ctx, sk, 0);
	cilium_dbg(ctx, DBG_SK_ASSIGN, -result, dbg_ctx);
	if (result == 0)
		result = CTX_ACT_OK;
	else
		result = DROP_PROXY_SET_FAILED;
	sk_release(sk);
out:
	return result;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "assign_socket",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct bpf_sock_tuple *tuple",
    " __u32 len",
    " __u8 nexthdr",
    " bool established"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
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
static __always_inline int
assign_socket(struct __ctx_buff *ctx,
	      struct bpf_sock_tuple *tuple, __u32 len,
	      __u8 nexthdr, bool established)
{
	/* Workaround: While the below functions are nearly identical in C
	 * implementation, the 'struct bpf_sock *' has a different verifier
	 * pointer type, which means we can't fold these implementations
	 * together.
	 */
	switch (nexthdr) {
	case IPPROTO_TCP:
		return assign_socket_tcp(ctx, tuple, len, established);
	case IPPROTO_UDP:
		return assign_socket_udp(ctx, tuple, len, established);
	}
	return DROP_PROXY_UNKNOWN_PROTO;
}

/**
 * combine_ports joins the specified ports in a manner consistent with
 * pkg/monitor/dataapth_debug.go to report the ports ino monitor messages.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 92,
  "endLine": 96,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "combine_ports",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 dport",
    " __u16 sport"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
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
static __always_inline __u32
combine_ports(__u16 dport, __u16 sport)
{
	return (bpf_ntohs(dport) << 16) | bpf_ntohs(sport);
}

#define CTX_REDIRECT_FN(NAME, CT_TUPLE_TYPE, SK_FIELD,				\
			DBG_LOOKUP_CODE, DADDR_DBG, SADDR_DBG)			\
/**										\
 * ctx_redirect_to_proxy_ingress4 / ctx_redirect_to_proxy_ingress6		\
 * @ctx			pointer to program context				\
 * @tuple		pointer to *scratch buffer* with packet tuple		\
 * @proxy_port		port to redirect traffic towards			\
 *										\
 * Prefetch the proxy socket and associate with the ctx. Must be run on tc	\
 * ingress. Will modify 'tuple'!						\
 */										\
static __always_inline int							\
NAME(struct __ctx_buff *ctx, CT_TUPLE_TYPE * ct_tuple, __be16 proxy_port)	\
{										\
	struct bpf_sock_tuple *tuple = (struct bpf_sock_tuple *)ct_tuple;	\
	__u8 nexthdr = ct_tuple->nexthdr;					\
	__u32 len = sizeof(tuple->SK_FIELD);					\
	__u16 port;								\
	int result;								\
										\
	/* The provided 'ct_tuple' is in the internal Cilium format, which	\
	 * reverses the source/destination ports as compared with the actual	\
	 * packet contents. 'bpf_sock_tuple' in the eBPF API needs these to	\
	 * match normal packet ordering to successfully look up the		\
	 * corresponding socket. So, swap them here.				\
	 */									\
	port = tuple->SK_FIELD.sport;						\
	tuple->SK_FIELD.sport = tuple->SK_FIELD.dport;				\
	tuple->SK_FIELD.dport = port;						\
										\
	/* Look for established socket locally first */				\
	cilium_dbg3(ctx, DBG_LOOKUP_CODE,					\
		    tuple->SK_FIELD.SADDR_DBG, tuple->SK_FIELD.DADDR_DBG,	\
		    combine_ports(tuple->SK_FIELD.dport, tuple->SK_FIELD.sport));	\
	result = assign_socket(ctx, tuple, len, nexthdr, true);			\
	if (result == CTX_ACT_OK)						\
		goto out;							\
										\
	/* if there's no established connection, locate the tproxy socket */	\
	tuple->SK_FIELD.dport = proxy_port;					\
	tuple->SK_FIELD.sport = 0;						\
	memset(&tuple->SK_FIELD.daddr, 0, sizeof(tuple->SK_FIELD.daddr));	\
	memset(&tuple->SK_FIELD.saddr, 0, sizeof(tuple->SK_FIELD.saddr));	\
	cilium_dbg3(ctx, DBG_LOOKUP_CODE,					\
		    tuple->SK_FIELD.SADDR_DBG, tuple->SK_FIELD.DADDR_DBG,	\
		    combine_ports(tuple->SK_FIELD.dport, tuple->SK_FIELD.sport));	\
	result = assign_socket(ctx, tuple, len, nexthdr, false);		\
										\
out:										\
	return result;								\
}

#ifdef ENABLE_IPV4
CTX_REDIRECT_FN(ctx_redirect_to_proxy_ingress4, struct ipv4_ct_tuple, ipv4,
		DBG_SK_LOOKUP4, daddr, saddr)
#endif
#ifdef ENABLE_IPV6
CTX_REDIRECT_FN(ctx_redirect_to_proxy_ingress6, struct ipv6_ct_tuple, ipv6,
		DBG_SK_LOOKUP6, daddr[3], saddr[3])
#endif
#undef CTX_REDIRECT_FN
#endif /* ENABLE_TPROXY */

/**
 * __ctx_redirect_to_proxy configures the ctx with the proxy mark and proxy
 * port number to ensure that the stack redirects the packet into the proxy.
 *
 * It is called from both ingress and egress side of endpoint devices.
 *
 * In regular veth mode:
 * * To apply egress policy, the egressing endpoint configures the mark,
 *   which returns CTX_ACT_OK to pass the packet to the stack in the context
 *   of the source device (stack ingress).
 * * To apply ingress policy, the egressing endpoint or netdev program tail
 *   calls into the policy program which configures the mark here, which
 *   returns CTX_ACT_OK to pass the packet to the stack in the context of the
 *   source device (netdev or egress endpoint device, stack ingress).
 *
 * In chaining mode with bridged endpoint devices:
 * * To apply egress policy, the egressing endpoint configures the mark,
 *   which is propagated via ctx_store_meta() in the caller. The redirect() call
 *   here redirects the packet to the ingress TC filter configured on the bridge
 *   master device.
 * * To apply ingress policy, the stack transmits the packet into the bridge
 *   master device which tail calls into the policy program for the ingress
 *   endpoint, which configures mark and cb[] as described for the egress path.
 *   The redirect() call here redirects the packet to the ingress TC filter
 *   configured on the bridge master device.
 * * In both cases for bridged endpoint devices, the bridge master device has
 *   a BPF program configured upon ingress to transfer the cb[] to the mark
 *   before passing the traffic up to the stack towards the proxy.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "__ctx__to_proxystruct __ctx_buff *ctx",
          " void *tuple __maybe_unused",
          "\t\t\t__be16 proxy_port",
          " bool from_host __maybe_unused",
          "\t\t\tbool ipv4 __maybe_unused"
        ]
      },
      {
        "opVar": "#ifdef ENABLE_IPV4\t\tif (ipv4)\t\t\tresult ",
        "inpVar": [
          " ctx__to_proxy_ingress4ctx",
          " tuple",
          " proxy_port"
        ]
      },
      {
        "opVar": "#endif #ifdef ENABLE_IPV6\t\tif (!ipv4)\t\t\tresult ",
        "inpVar": [
          " ctx__to_proxy_ingress6ctx",
          " tuple",
          " proxy_port"
        ]
      }
    ]
  },
  "startLine": 190,
  "endLine": 220,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "__ctx_redirect_to_proxy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " void * tuple __maybe_unused",
    " __be16 proxy_port",
    " bool from_host __maybe_unused",
    " bool ipv4 __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "sched_act"
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
static __always_inline int
__ctx_redirect_to_proxy(struct __ctx_buff *ctx, void *tuple __maybe_unused,
			__be16 proxy_port, bool from_host __maybe_unused,
			bool ipv4 __maybe_unused)
{
	int result __maybe_unused = CTX_ACT_OK;

#ifdef ENABLE_TPROXY
	if (!from_host)
		ctx->mark |= MARK_MAGIC_TO_PROXY;
	else
#endif
		ctx->mark = MARK_MAGIC_TO_PROXY | proxy_port << 16;

	cilium_dbg(ctx, DBG_CAPTURE_PROXY_PRE, proxy_port, 0);

#ifdef ENABLE_TPROXY
	if (proxy_port && !from_host) {
#ifdef ENABLE_IPV4
		if (ipv4)
			result = ctx_redirect_to_proxy_ingress4(ctx, tuple, proxy_port);
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
		if (!ipv4)
			result = ctx_redirect_to_proxy_ingress6(ctx, tuple, proxy_port);
#endif /* ENABLE_IPV6 */
	}
#endif /* ENABLE_TPROXY */
	ctx_change_type(ctx, PACKET_HOST); /* Required for ingress packets from overlay */
	return result;
}

#ifdef ENABLE_IPV4
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx__to_proxy4struct __ctx_buff *ctx",
          " void *tuple __maybe_unused",
          "\t\t       __be16 proxy_port",
          " bool from_host __maybe_unused"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn __ctx__to_proxyctx",
          " tuple",
          " proxy_port",
          " from_host",
          " true"
        ]
      }
    ]
  },
  "startLine": 223,
  "endLine": 228,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "ctx_redirect_to_proxy4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " void * tuple __maybe_unused",
    " __be16 proxy_port",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "sched_act"
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
static __always_inline int
ctx_redirect_to_proxy4(struct __ctx_buff *ctx, void *tuple __maybe_unused,
		       __be16 proxy_port, bool from_host __maybe_unused)
{
	return __ctx_redirect_to_proxy(ctx, tuple, proxy_port, from_host, true);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx__to_proxy6struct __ctx_buff *ctx",
          " void *tuple __maybe_unused",
          "\t\t       __be16 proxy_port",
          " bool from_host __maybe_unused"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn __ctx__to_proxyctx",
          " tuple",
          " proxy_port",
          " from_host",
          " false"
        ]
      }
    ]
  },
  "startLine": 232,
  "endLine": 237,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "ctx_redirect_to_proxy6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " void * tuple __maybe_unused",
    " __be16 proxy_port",
    " bool from_host __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "sched_act"
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
static __always_inline int
ctx_redirect_to_proxy6(struct __ctx_buff *ctx, void *tuple __maybe_unused,
		       __be16 proxy_port, bool from_host __maybe_unused)
{
	return __ctx_redirect_to_proxy(ctx, tuple, proxy_port, from_host, false);
}
#endif /* ENABLE_IPV6 */

#ifdef ENABLE_TPROXY
#define IP_TUPLE_EXTRACT_FN(NAME, PREFIX)				\
/**									\
 * extract_tuple4 / extract_tuple6					\
 *									\
 * Extracts the packet 5-tuple into 'tuple'.				\
 *									\
 * Note that it doesn't fully initialize 'tuple' as the directionality	\
 * bit is unused in the proxy paths.					\
 */									\
static __always_inline int						\
NAME(struct __ctx_buff *ctx, struct PREFIX ## _ct_tuple *tuple)		\
{									\
	int err, l4_off;						\
									\
	err = PREFIX ## _extract_tuple(ctx, tuple, &l4_off);		\
	if (err != CTX_ACT_OK)						\
		return err;						\
									\
	if (ctx_load_bytes(ctx, l4_off, &tuple->dport, 4) < 0)		\
		return DROP_CT_INVALID_HDR;				\
									\
	__ ## PREFIX ## _ct_tuple_reverse(tuple);			\
									\
	return CTX_ACT_OK;						\
}

#ifdef ENABLE_IPV4
IP_TUPLE_EXTRACT_FN(extract_tuple4, ipv4)
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
IP_TUPLE_EXTRACT_FN(extract_tuple6, ipv6)
#endif /* ENABLE_IPV6 */
#endif /* ENABLE_TPROXY */

/**
 * ctx_redirect_to_proxy_first() applies changes to the context to forward
 * the packet towards the proxy. It is designed to run as the first function
 * that accesses the context from the current BPF program.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx__to_proxy_firststruct __ctx_buff *ctx",
          " __be16 proxy_port"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy_ingress6ctx",
          " &tuple",
          " proxy_port"
        ]
      },
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx__to_proxy_ingress4ctx",
          " &tuple",
          " proxy_port"
        ]
      }
    ]
  },
  "startLine": 280,
  "endLine": 337,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "ctx_redirect_to_proxy_first",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __be16 proxy_port"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "xdp",
    "sched_act"
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
static __always_inline int
ctx_redirect_to_proxy_first(struct __ctx_buff *ctx, __be16 proxy_port)
{
	int ret = CTX_ACT_OK;
#if defined(ENABLE_TPROXY)
	__u16 proto;

	/**
	 * For reply traffic to egress proxy for a local endpoint, we skip the
	 * policy & proxy_port lookup and just hairpin & rely on local stack
	 * routing via ctx->mark to ensure that the return traffic reaches the
	 * proxy. This is only relevant for endpoint-routes mode but we don't
	 * have a macro for this so the logic applies unconditionally here.
	 * See ct_state.proxy_redirect usage in bpf_lxc.c for more info.
	 */
	if (!proxy_port)
		goto mark;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	ret = DROP_UNKNOWN_L3;
	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6): {
		struct ipv6_ct_tuple tuple;

		ret = extract_tuple6(ctx, &tuple);
		if (ret < 0)
			return ret;
		ret = ctx_redirect_to_proxy_ingress6(ctx, &tuple, proxy_port);
		break;
	}
#endif /* ENABLE_IPV6 */
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP): {
		struct ipv4_ct_tuple tuple;

		ret = extract_tuple4(ctx, &tuple);
		if (ret < 0)
			return ret;
		ret = ctx_redirect_to_proxy_ingress4(ctx, &tuple, proxy_port);
		break;
	}
#endif /* ENABLE_IPV4 */
	default:
		goto out;
	}
#endif /* ENABLE_TPROXY */

mark: __maybe_unused
	cilium_dbg(ctx, DBG_CAPTURE_PROXY_POST, proxy_port, 0);
	ctx->mark = MARK_MAGIC_TO_PROXY | (proxy_port << 16);
	ctx_change_type(ctx, PACKET_HOST);

out: __maybe_unused
	return ret;
}

/**
 * tc_index_skip_ingress_proxy - returns true if packet originates from ingress proxy
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 342,
  "endLine": 351,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "tc_index_skip_ingress_proxy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
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
static __always_inline bool tc_index_skip_ingress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_INGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_INGRESS_PROXY;
}

/**
 * tc_index_skip_egress_proxy - returns true if packet originates from egress proxy
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 356,
  "endLine": 365,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/proxy.h",
  "funcName": "tc_index_skip_egress_proxy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "static__always_inlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "perf_event",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_device",
    "xdp",
    "sk_msg",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "tracepoint"
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
static __always_inline bool tc_index_skip_egress_proxy(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;
#ifdef DEBUG
	if (tc_index & TC_INDEX_F_SKIP_EGRESS_PROXY)
		cilium_dbg(ctx, DBG_SKIP_PROXY, tc_index, 0);
#endif

	return tc_index & TC_INDEX_F_SKIP_EGRESS_PROXY;
}
#endif /* __LIB_PROXY_H_ */
