// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <netdev_config.h>

#define SKIP_POLICY_MAP	1
#define SKIP_CALLS_MAP	1

#include "lib/common.h"
#include "lib/lb.h"
#include "lib/eps.h"
#include "lib/identity.h"
#include "lib/metrics.h"
#include "lib/nat_46x64.h"

#define SYS_REJECT	0
#define SYS_PROCEED	1

#ifndef HOST_NETNS_COOKIE
# define HOST_NETNS_COOKIE   get_netns_cookie(NULL)
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 27,
  "endLine": 31,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "is_v4_loopback",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__be32 daddr"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool is_v4_loopback (__be32 daddr)\n",
    "{\n",
    "    return (daddr & bpf_htonl (0x7f000000)) == bpf_htonl (0x7f000000);\n",
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
static __always_inline __maybe_unused bool is_v4_loopback(__be32 daddr)
{
	/* Check for 127.0.0.0/8 range, RFC3330. */
	return (daddr & bpf_htonl(0x7f000000)) == bpf_htonl(0x7f000000);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 33,
  "endLine": 39,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "is_v6_loopback",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const union v6addr *daddr"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool is_v6_loopback (const union v6addr *daddr)\n",
    "{\n",
    "    union v6addr loopback = {\n",
    "        .addr [15] = 1,}\n",
    "    ;\n",
    "    return ipv6_addrcmp (&loopback, daddr) == 0;\n",
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
static __always_inline __maybe_unused bool is_v6_loopback(const union v6addr *daddr)
{
	/* Check for ::1/128, RFC4291. */
	union v6addr loopback = { .addr[15] = 1, };

	return ipv6_addrcmp(&loopback, daddr) == 0;
}

/* Hack due to missing narrow ctx access. */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 42,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_dst_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__maybe_unused__be16",
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
    "static __always_inline __maybe_unused __be16 ctx_dst_port (const struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    volatile __u32 dport = ctx->user_port;\n",
    "    return (__be16) dport;\n",
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
static __always_inline __maybe_unused __be16
ctx_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;

	return (__be16)dport;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 56,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_src_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock *ctx"
  ],
  "output": "static__always_inline__maybe_unused__be16",
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
    "static __always_inline __maybe_unused __be16 ctx_src_port (const struct bpf_sock *ctx)\n",
    "{\n",
    "    volatile __u16 sport = (__u16) ctx->src_port;\n",
    "    return (__be16) bpf_htons (sport);\n",
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
static __always_inline __maybe_unused __be16
ctx_src_port(const struct bpf_sock *ctx)
{
	volatile __u16 sport = (__u16)ctx->src_port;

	return (__be16)bpf_htons(sport);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 58,
  "endLine": 62,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_set_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " __be16 dport"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
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
    "static __always_inline __maybe_unused void ctx_set_port (struct bpf_sock_addr *ctx, __be16 dport)\n",
    "{\n",
    "    ctx->user_port = (__u32) dport;\n",
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
static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
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
          "Return Type": "u32",
          "Description": "Retrieve the classid for the current task , i. e. for the net_cls cgroup to which <[ skb ]>(IP: 0) belongs. This helper can be used on TC egress path , but not on ingress. The net_cls cgroup provides an interface to tag network packets based on a user-provided identifier for all traffic coming from the tasks belonging to the related cgroup. See also the related kernel documentation , available from the Linux sources in file Documentation/admin-guide/cgroup-v1/net_cls. rst. The Linux kernel has two versions for cgroups: there are cgroups v1 and cgroups v2. Both are available to users , who can use a mixture of them , but note that the net_cls cgroup is for cgroup v1 only. This makes it incompatible with BPF programs run on cgroups , which is a cgroup-v2-only feature (a socket can only hold data for one version of cgroups at a time). This helper is only available is the kernel was compiled with the CONFIG_CGROUP_NET_CLASSID configuration option set to \"y\" or to \"m\" ",
          "Return": " The classid, or 0 for the default unconfigured classid.",
          "Function Name": "get_cgroup_classid",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_cgroup_classid": [
      {
        "opVar": "#ifdef ENABLE_MKE\t\treturn get_cgroup_classid() ",
        "inpVar": [
          ""
        ]
      }
    ]
  },
  "startLine": 64,
  "endLine": 72,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "task_in_extended_hostns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__always_inline__maybe_unusedbool",
  "helper": [
    "get_cgroup_classid"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "sched_act",
    "lwt_seg6local",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static __always_inline __maybe_unused bool task_in_extended_hostns (void)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_MKE\n",
    "    return get_cgroup_classid () == MKE_HOST;\n",
    "\n",
    "#else\n",
    "    return false;\n",
    "\n",
    "#endif\n",
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
static __always_inline __maybe_unused bool task_in_extended_hostns(void)
{
#ifdef ENABLE_MKE
	/* Extension for non-Cilium managed containers on MKE. */
	return get_cgroup_classid() == MKE_HOST;
#else
	return false;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 74,
  "endLine": 89,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_in_hostns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void * ctx __maybe_unused",
    " __net_cookie *cookie"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool ctx_in_hostns (void * ctx __maybe_unused, __net_cookie *cookie)\n",
    "{\n",
    "\n",
    "#ifdef BPF_HAVE_NETNS_COOKIE\n",
    "    __net_cookie own_cookie = get_netns_cookie (ctx);\n",
    "    if (cookie)\n",
    "        *cookie = own_cookie;\n",
    "    return own_cookie == HOST_NETNS_COOKIE || task_in_extended_hostns ();\n",
    "\n",
    "#else\n",
    "    if (cookie)\n",
    "        *cookie = 0;\n",
    "    return true;\n",
    "\n",
    "#endif\n",
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
static __always_inline __maybe_unused bool
ctx_in_hostns(void *ctx __maybe_unused, __net_cookie *cookie)
{
#ifdef BPF_HAVE_NETNS_COOKIE
	__net_cookie own_cookie = get_netns_cookie(ctx);

	if (cookie)
		*cookie = own_cookie;
	return own_cookie == HOST_NETNS_COOKIE ||
	       task_in_extended_hostns();
#else
	if (cookie)
		*cookie = 0;
	return true;
#endif
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
          "Return Type": "u32",
          "Description": "Get a pseudo-random number. From a security point of view , this helper uses its own pseudo-random internal state , and cannot be used to infer the seed of other random functions in the kernel. However , it is essential to note that the generator used by the helper is not cryptographically secure. ",
          "Return": " A random 32-bit unsigned value.",
          "Function Name": "get_prandom_u32",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        },
        {
          "Project": "cilium",
          "Return Type": "u64",
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_socket_cookie": [
      {
        "opVar": "NA",
        "inpVar": [
          "#ifdef BPF_HAVE_SOCKET_COOKIE\t\treturn ctx"
        ]
      }
    ],
    "get_prandom_u32": [
      {
        "opVar": "#else\treturn ctx->protocol ",
        "inpVar": [
          ""
        ]
      }
    ]
  },
  "startLine": 91,
  "endLine": 119,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock_local_cookie",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__maybe_unused__sock_cookie",
  "helper": [
    "get_prandom_u32",
    "get_socket_cookie"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "sk_skb",
    "cgroup_skb",
    "sock_ops"
  ],
  "source": [
    "static __always_inline __maybe_unused __sock_cookie sock_local_cookie (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "\n",
    "#ifdef BPF_HAVE_SOCKET_COOKIE\n",
    "    return get_socket_cookie (ctx);\n",
    "\n",
    "#else\n",
    "    return ctx->protocol == IPPROTO_TCP ? get_prandom_u32 () : 0;\n",
    "\n",
    "#endif\n",
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
static __always_inline __maybe_unused
__sock_cookie sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef BPF_HAVE_SOCKET_COOKIE
	/* prandom() breaks down on UDP, hence preference is on
	 * socket cookie as built-in selector. On older kernels,
	 * get_socket_cookie() provides a unique per netns cookie
	 * for the life-time of the socket. For newer kernels this
	 * is fixed to be a unique system _global_ cookie. Older
	 * kernels could have a cookie collision when two pods with
	 * different netns talk to same service backend, but that
	 * is fine since we always reverse translate to the same
	 * service IP/port pair. The only case that could happen
	 * for older kernels is that we have a cookie collision
	 * where one pod talks to the service IP/port and the
	 * other pod talks to that same specific backend IP/port
	 * directly _w/o_ going over service IP/port. Then the
	 * reverse sock addr is translated to the service IP/port.
	 * With a global socket cookie this collision cannot take
	 * place. There, only the even more unlikely case could
	 * happen where the same UDP socket talks first to the
	 * service and then to the same selected backend IP/port
	 * directly which can be considered negligible.
	 */
	return get_socket_cookie(ctx);
#else
	return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 121,
  "endLine": 131,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock_is_health_check",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool sock_is_health_check (struct bpf_sock_addr * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_HEALTH_CHECK\n",
    "    int val;\n",
    "    if (!get_socket_opt (ctx, SOL_SOCKET, SO_MARK, &val, sizeof (val)))\n",
    "        return val == MARK_MAGIC_HEALTH;\n",
    "\n",
    "#endif\n",
    "    return false;\n",
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
static __always_inline __maybe_unused
bool sock_is_health_check(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_HEALTH_CHECK
	int val;

	if (!get_socket_opt(ctx, SOL_SOCKET, SO_MARK, &val, sizeof(val)))
		return val == MARK_MAGIC_HEALTH;
#endif
	return false;
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
          "Return Type": "u32",
          "Description": "Get a pseudo-random number. From a security point of view , this helper uses its own pseudo-random internal state , and cannot be used to infer the seed of other random functions in the kernel. However , it is essential to note that the generator used by the helper is not cryptographically secure. ",
          "Return": " A random 32-bit unsigned value.",
          "Function Name": "get_prandom_u32",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_prandom_u32": [
      {
        "opVar": "\treturn ctx->protocol ",
        "inpVar": [
          ""
        ]
      }
    ]
  },
  "startLine": 133,
  "endLine": 138,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock_select_slot",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u64",
  "helper": [
    "get_prandom_u32"
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
    "static __always_inline __maybe_unused __u64 sock_select_slot (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    return ctx->protocol == IPPROTO_TCP ? get_prandom_u32 () : sock_local_cookie (ctx);\n",
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
static __always_inline __maybe_unused
__u64 sock_select_slot(struct bpf_sock_addr *ctx)
{
	return ctx->protocol == IPPROTO_TCP ?
	       get_prandom_u32() : sock_local_cookie(ctx);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 140,
  "endLine": 156,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock_proto_enabled",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 proto"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool sock_proto_enabled (__u32 proto)\n",
    "{\n",
    "    switch (proto) {\n",
    "\n",
    "#ifdef ENABLE_SOCKET_LB_TCP\n",
    "    case IPPROTO_TCP :\n",
    "        return true;\n",
    "\n",
    "#endif /* ENABLE_SOCKET_LB_TCP */\n",
    "\n",
    "#ifdef ENABLE_SOCKET_LB_UDP\n",
    "    case IPPROTO_UDPLITE :\n",
    "    case IPPROTO_UDP :\n",
    "        return true;\n",
    "\n",
    "#endif /* ENABLE_SOCKET_LB_UDP */\n",
    "    default :\n",
    "        return false;\n",
    "    }\n",
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
static __always_inline __maybe_unused
bool sock_proto_enabled(__u32 proto)
{
	switch (proto) {
#ifdef ENABLE_SOCKET_LB_TCP
	case IPPROTO_TCP:
		return true;
#endif /* ENABLE_SOCKET_LB_TCP */
#ifdef ENABLE_SOCKET_LB_UDP
	case IPPROTO_UDPLITE:
	case IPPROTO_UDP:
		return true;
#endif /* ENABLE_SOCKET_LB_UDP */
	default:
		return false;
	}
}

#ifdef ENABLE_IPV4
#if defined(ENABLE_SOCKET_LB_UDP) || defined(ENABLE_SOCKET_LB_PEER)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_revnat_tuple);
	__type(value, struct ipv4_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB4_REVERSE_NAT_SK_MAP_SIZE);
} LB4_REVERSE_NAT_SK_MAP __section_maps_btf;

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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\ttmp ",
        "inpVar": [
          " &LB4_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "\tif (!tmp || memcmp(tmp, &val, sizeof(val)))\t\tret ",
        "inpVar": [
          " &LB4_REVERSE_NAT_SK_MAP",
          " &key",
          "\t\t\t\t      &val",
          " 0"
        ]
      }
    ]
  },
  "startLine": 168,
  "endLine": 190,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_update_revnat",
  "updateMaps": [
    " LB4_REVERSE_NAT_SK_MAP"
  ],
  "readMaps": [
    "  LB4_REVERSE_NAT_SK_MAP"
  ],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const struct lb4_backend *backend",
    " const struct lb4_key *orig_key",
    " __u16 rev_nat_id"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_update_elem",
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
    "sk_reuseport",
    "cgroup_sysctl",
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
    "static __always_inline int sock4_update_revnat (struct bpf_sock_addr *ctx, const struct lb4_backend *backend, const struct lb4_key *orig_key, __u16 rev_nat_id)\n",
    "{\n",
    "    struct ipv4_revnat_entry val = {}, *tmp;\n",
    "    struct ipv4_revnat_tuple key = {}\n",
    "    ;\n",
    "    int ret = 0;\n",
    "    key.cookie = sock_local_cookie (ctx);\n",
    "    key.address = backend->address;\n",
    "    key.port = backend->port;\n",
    "    val.address = orig_key->address;\n",
    "    val.port = orig_key->dport;\n",
    "    val.rev_nat_index = rev_nat_id;\n",
    "    tmp = map_lookup_elem (& LB4_REVERSE_NAT_SK_MAP, & key);\n",
    "    if (!tmp || memcmp (tmp, &val, sizeof (val)))\n",
    "        ret = map_update_elem (&LB4_REVERSE_NAT_SK_MAP, &key, &val, 0);\n",
    "    return ret;\n",
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
static __always_inline int sock4_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb4_backend *backend,
					       const struct lb4_key *orig_key,
					       __u16 rev_nat_id)
{
	struct ipv4_revnat_entry val = {}, *tmp;
	struct ipv4_revnat_tuple key = {};
	int ret = 0;

	key.cookie = sock_local_cookie(ctx);
	key.address = backend->address;
	key.port = backend->port;

	val.address = orig_key->address;
	val.port = orig_key->dport;
	val.rev_nat_index = rev_nat_id;

	tmp = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
	if (!tmp || memcmp(tmp, &val, sizeof(val)))
		ret = map_update_elem(&LB4_REVERSE_NAT_SK_MAP, &key,
				      &val, 0);
	return ret;
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 192,
  "endLine": 199,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_update_revnat",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused",
    " struct lb4_backend * backend __maybe_unused",
    " struct lb4_key * orig_key __maybe_unused",
    " __u16 rev_nat_id __maybe_unused"
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
    "static __always_inline int sock4_update_revnat (struct bpf_sock_addr * ctx __maybe_unused, struct lb4_backend * backend __maybe_unused, struct lb4_key * orig_key __maybe_unused, __u16 rev_nat_id __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
static __always_inline
int sock4_update_revnat(struct bpf_sock_addr *ctx __maybe_unused,
			struct lb4_backend *backend __maybe_unused,
			struct lb4_key *orig_key __maybe_unused,
			__u16 rev_nat_id __maybe_unused)
{
	return 0;
}
#endif /* ENABLE_SOCKET_LB_UDP || ENABLE_SOCKET_LB_PEER */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 202,
  "endLine": 218,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_skip_xlate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb4_service *svc",
    " __be32 address"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool sock4_skip_xlate (struct lb4_service *svc, __be32 address)\n",
    "{\n",
    "    if (lb4_to_lb6_service (svc))\n",
    "        return true;\n",
    "    if (lb4_svc_is_external_ip (svc) || (lb4_svc_is_hostport (svc) && !is_v4_loopback (address))) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = ipcache_lookup4 (& IPCACHE_MAP, address, V4_CACHE_KEY_LEN);\n",
    "        if (info == NULL || info->sec_label != HOST_ID)\n",
    "            return true;\n",
    "    }\n",
    "    return false;\n",
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
static __always_inline bool
sock4_skip_xlate(struct lb4_service *svc, __be32 address)
{
	if (lb4_to_lb6_service(svc))
		return true;
	if (lb4_svc_is_external_ip(svc) ||
	    (lb4_svc_is_hostport(svc) && !is_v4_loopback(address))) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup4(&IPCACHE_MAP, address,
				       V4_CACHE_KEY_LEN);
		if (info == NULL || info->sec_label != HOST_ID)
			return true;
	}

	return false;
}

#ifdef ENABLE_NODEPORT
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 221,
  "endLine": 251,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "*sock4_wildcard_lookup",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb4_key * key __maybe_unused",
    " const bool include_remote_hosts __maybe_unused",
    " const bool inv_match __maybe_unused",
    " const bool in_hostns __maybe_unused"
  ],
  "output": "static__always_inlinestructlb4_service",
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
    "static __always_inline struct lb4_service *sock4_wildcard_lookup (struct lb4_key * key __maybe_unused, const bool include_remote_hosts __maybe_unused, const bool inv_match __maybe_unused, const bool in_hostns __maybe_unused)\n",
    "{\n",
    "    struct remote_endpoint_info *info;\n",
    "    __u16 service_port;\n",
    "    service_port = bpf_ntohs (key -> dport);\n",
    "    if ((service_port < NODEPORT_PORT_MIN || service_port > NODEPORT_PORT_MAX) ^ inv_match)\n",
    "        return NULL;\n",
    "    if (in_hostns && is_v4_loopback (key->address))\n",
    "        goto wildcard_lookup;\n",
    "    info = ipcache_lookup4 (& IPCACHE_MAP, key -> address, V4_CACHE_KEY_LEN);\n",
    "    if (info != NULL && (info->sec_label == HOST_ID || (include_remote_hosts && identity_is_remote_node (info->sec_label))))\n",
    "        goto wildcard_lookup;\n",
    "    return NULL;\n",
    "wildcard_lookup :\n",
    "    key->address = 0;\n",
    "    return lb4_lookup_service (key, true);\n",
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
static __always_inline struct lb4_service *
sock4_wildcard_lookup(struct lb4_key *key __maybe_unused,
		      const bool include_remote_hosts __maybe_unused,
		      const bool inv_match __maybe_unused,
		      const bool in_hostns __maybe_unused)
{
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if ((service_port < NODEPORT_PORT_MIN ||
	     service_port > NODEPORT_PORT_MAX) ^ inv_match)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v4_loopback(key->address))
		goto wildcard_lookup;

	info = ipcache_lookup4(&IPCACHE_MAP, key->address, V4_CACHE_KEY_LEN);
	if (info != NULL && (info->sec_label == HOST_ID ||
	    (include_remote_hosts && identity_is_remote_node(info->sec_label))))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	key->address = 0;
	return lb4_lookup_service(key, true);
}
#endif /* ENABLE_NODEPORT */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 254,
  "endLine": 272,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "*sock4_wildcard_lookup_full",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb4_key * key __maybe_unused",
    " const bool in_hostns __maybe_unused"
  ],
  "output": "static__always_inlinestructlb4_service",
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
    "static __always_inline struct lb4_service *sock4_wildcard_lookup_full (struct lb4_key * key __maybe_unused, const bool in_hostns __maybe_unused)\n",
    "{\n",
    "    struct lb4_service *svc = NULL;\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    svc = sock4_wildcard_lookup (key, true, false, in_hostns);\n",
    "    if (svc && !lb4_svc_is_nodeport (svc))\n",
    "        svc = NULL;\n",
    "    if (!svc) {\n",
    "        svc = sock4_wildcard_lookup (key, false, true, in_hostns);\n",
    "        if (svc && !lb4_svc_is_hostport (svc))\n",
    "            svc = NULL;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "    return svc;\n",
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
static __always_inline struct lb4_service *
sock4_wildcard_lookup_full(struct lb4_key *key __maybe_unused,
			   const bool in_hostns __maybe_unused)
{
	struct lb4_service *svc = NULL;

#ifdef ENABLE_NODEPORT
	svc = sock4_wildcard_lookup(key, true, false, in_hostns);
	if (svc && !lb4_svc_is_nodeport(svc))
		svc = NULL;
	if (!svc) {
		svc = sock4_wildcard_lookup(key, false, true,
					    in_hostns);
		if (svc && !lb4_svc_is_hostport(svc))
			svc = NULL;
	}
#endif /* ENABLE_NODEPORT */
	return svc;
}

/* Service translation logic for a local-redirect service can cause packets to
 * be looped back to a service node-local backend after translation. This can
 * happen when the node-local backend itself tries to connect to the service
 * frontend for which it acts as a backend. There are cases where this can break
 * traffic flow if the backend needs to forward the redirected traffic to the
 * actual service frontend. Hence, allow service translation for pod traffic
 * getting redirected to backend (across network namespaces), but skip service
 * translation for backend to itself or another service backend within the same
 * namespace. Currently only v4 and v4-in-v6, but no plain v6 is supported.
 *
 * For example, in EKS cluster, a local-redirect service exists with the AWS
 * metadata IP, port as the frontend <169.254.169.254, 80> and kiam proxy as a
 * backend Pod. When traffic destined to the frontend originates from the kiam
 * Pod in namespace ns1 (host ns when the kiam proxy Pod is deployed in
 * hostNetwork mode or regular Pod ns) and the Pod is selected as a backend, the
 * traffic would get looped back to the proxy Pod. Identify such cases by doing
 * a socket lookup for the backend <ip, port> in its namespace, ns1, and skip
 * service translation.
 */
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
        },
        {
          "Project": "cilium",
          "Return Type": "struct sock*",
          "Description": "Look for TCP socket matching <[ tuple ]>(IP: 1) , optionally in a child network namespace netns. The return value must be checked , and if non-NULL , released via sk_release(). The <[ ctx ]>(IP: 0) should point to the context of the program , such as the skb or socket (depending on the hook in use). This is used to determine the base network namespace for the lookup. <[ tuple_size ]>(IP: 2) must be one of: sizeof(tuple->ipv4) Look for an IPv4 socket. sizeof(tuple->ipv6) Look for an IPv6 socket. If the <[ netns ]>(IP: 3) is a negative signed 32-bit integer , then the socket lookup table in the <[ netns ]>(IP: 3) associated with the <[ ctx ]>(IP: 0) will will be used. For the TC hooks , this is the <[ netns ]>(IP: 3) of the device in the skb. For socket hooks , this is the <[ netns ]>(IP: 3) of the socket. If <[ netns ]>(IP: 3) is any other signed 32-bit value greater than or equal to zero then it specifies the ID of the <[ netns ]>(IP: 3) relative to the <[ netns ]>(IP: 3) associated with the ctx. <[ netns ]>(IP: 3) values beyond the range of 32-bit integers are reserved for future use. All values for <[ flags ]>(IP: 4) are reserved for future usage , and must be left at zero. This helper is available only if the kernel was compiled with CONFIG_NET configuration option. ",
          "Return": " Pointer to struct  sock, or NULL in case of failure.   For  sockets  with                     reuseport  option,  the  struct  sock result is from reuse->socks[] using                     the hash of the tuple.",
          "Function Name": "sk_lookup_tcp",
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
    "sk_lookup_tcp": [
      {
        "opVar": "\tcase IPPROTO_TCP:\t\tsk ",
        "inpVar": [
          " ctx",
          " &tuple",
          " sizeoftuple.ipv4",
          "\t\t\t\t   BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_lookup_udp": [
      {
        "opVar": "\tcase IPPROTO_UDP:\t\tsk ",
        "inpVar": [
          " ctx",
          " &tuple",
          " sizeoftuple.ipv4",
          "\t\t\t\t   BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_release": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tsk"
        ]
      }
    ]
  },
  "startLine": 293,
  "endLine": 321,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_skip_xlate_if_same_netns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused",
    " const struct lb4_backend * backend __maybe_unused"
  ],
  "output": "static__always_inlinebool",
  "helper": [
    "sk_lookup_udp",
    "sk_lookup_tcp",
    "sk_release"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "xdp",
    "sched_cls",
    "sched_act",
    "sk_skb"
  ],
  "source": [
    "static __always_inline bool sock4_skip_xlate_if_same_netns (struct bpf_sock_addr * ctx __maybe_unused, const struct lb4_backend * backend __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef BPF_HAVE_SOCKET_LOOKUP\n",
    "    struct bpf_sock_tuple tuple = {\n",
    "        .ipv4.daddr = backend->address,\n",
    "        .ipv4.dport = backend->port,}\n",
    "    ;\n",
    "    struct bpf_sock *sk = NULL;\n",
    "    switch (ctx->protocol) {\n",
    "    case IPPROTO_TCP :\n",
    "        sk = sk_lookup_tcp (ctx, &tuple, sizeof (tuple.ipv4), BPF_F_CURRENT_NETNS, 0);\n",
    "        break;\n",
    "    case IPPROTO_UDP :\n",
    "        sk = sk_lookup_udp (ctx, &tuple, sizeof (tuple.ipv4), BPF_F_CURRENT_NETNS, 0);\n",
    "        break;\n",
    "    }\n",
    "    if (sk) {\n",
    "        sk_release (sk);\n",
    "        return true;\n",
    "    }\n",
    "\n",
    "#endif /* BPF_HAVE_SOCKET_LOOKUP */\n",
    "    return false;\n",
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
static __always_inline bool
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx __maybe_unused,
			       const struct lb4_backend *backend __maybe_unused)
{
#ifdef BPF_HAVE_SOCKET_LOOKUP
	struct bpf_sock_tuple tuple = {
		.ipv4.daddr = backend->address,
		.ipv4.dport = backend->port,
	};
	struct bpf_sock *sk = NULL;

	switch (ctx->protocol) {
	case IPPROTO_TCP:
		sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	case IPPROTO_UDP:
		sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	}

	if (sk) {
		sk_release(sk);
		return true;
	}
#endif /* BPF_HAVE_SOCKET_LOOKUP */
	return false;
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
          "\t\tif lb4_svc_is_localsvc &&\t    sock4_skip_xlate_if_same_netnsctx_full",
          " backend\t\treturn -ENXIO"
        ]
      }
    ]
  },
  "startLine": 323,
  "endLine": 458,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock4_xlate_fwd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " struct bpf_sock_addr *ctx_full",
    " const bool udp_only"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int __sock4_xlate_fwd (struct bpf_sock_addr *ctx, struct bpf_sock_addr *ctx_full, const bool udp_only)\n",
    "{\n",
    "    union lb4_affinity_client_id id;\n",
    "    const bool in_hostns = ctx_in_hostns (ctx_full, & id.client_cookie);\n",
    "    struct lb4_backend *backend;\n",
    "    struct lb4_service *svc;\n",
    "    struct lb4_key key = {\n",
    "        .address = ctx->user_ip4,\n",
    "        .dport = ctx_dst_port (ctx),}, orig_key = key;\n",
    "    struct lb4_service *backend_slot;\n",
    "    bool backend_from_affinity = false;\n",
    "    __u32 backend_id = 0;\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    struct lb4_backend l7backend;\n",
    "\n",
    "#endif\n",
    "    if (is_defined (ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)\n",
    "        return -ENXIO;\n",
    "    if (!udp_only && !sock_proto_enabled (ctx->protocol))\n",
    "        return -ENOTSUP;\n",
    "    svc = lb4_lookup_service (& key, true);\n",
    "    if (!svc)\n",
    "        svc = sock4_wildcard_lookup_full (&key, in_hostns);\n",
    "    if (!svc)\n",
    "        return -ENXIO;\n",
    "    if (sock4_skip_xlate (svc, orig_key.address))\n",
    "        return -EPERM;\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    if (lb4_svc_is_l7loadbalancer (svc)) {\n",
    "        if (is_defined (BPF_HAVE_NETNS_COOKIE) && in_hostns) {\n",
    "            l7backend.address = bpf_htonl (0x7f000001);\n",
    "            l7backend.port = (__be16) svc->l7_lb_proxy_port;\n",
    "            l7backend.proto = 0;\n",
    "            l7backend.flags = 0;\n",
    "            backend = &l7backend;\n",
    "            goto out;\n",
    "        }\n",
    "        return 0;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "    if (lb4_svc_is_affinity (svc)) {\n",
    "        backend_id = lb4_affinity_backend_id_by_netns (svc, & id);\n",
    "        backend_from_affinity = true;\n",
    "        if (backend_id != 0) {\n",
    "            backend = __lb4_lookup_backend (backend_id);\n",
    "            if (!backend)\n",
    "                backend_id = 0;\n",
    "        }\n",
    "    }\n",
    "    if (backend_id == 0) {\n",
    "        backend_from_affinity = false;\n",
    "        key.backend_slot = (sock_select_slot (ctx_full) % svc->count) + 1;\n",
    "        backend_slot = __lb4_lookup_backend_slot (& key);\n",
    "        if (!backend_slot) {\n",
    "            update_metrics (0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);\n",
    "            return -ENOENT;\n",
    "        }\n",
    "        backend_id = backend_slot->backend_id;\n",
    "        backend = __lb4_lookup_backend (backend_id);\n",
    "    }\n",
    "    if (!backend) {\n",
    "        update_metrics (0, METRIC_EGRESS, REASON_LB_NO_BACKEND);\n",
    "        return -ENOENT;\n",
    "    }\n",
    "    if (lb4_svc_is_localredirect (svc) && sock4_skip_xlate_if_same_netns (ctx_full, backend))\n",
    "        return -ENXIO;\n",
    "    if (lb4_svc_is_affinity (svc) && !backend_from_affinity)\n",
    "        lb4_update_affinity_by_netns (svc, &id, backend_id);\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "out :\n",
    "\n",
    "#endif\n",
    "    if (sock4_update_revnat (ctx_full, backend, &orig_key, svc->rev_nat_index) < 0) {\n",
    "        update_metrics (0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);\n",
    "        return -ENOMEM;\n",
    "    }\n",
    "    ctx->user_ip4 = backend->address;\n",
    "    ctx_set_port (ctx, backend->port);\n",
    "    return 0;\n",
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
static __always_inline int __sock4_xlate_fwd(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full,
					     const bool udp_only)
{
	union lb4_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx_full, &id.client_cookie);
	struct lb4_backend *backend;
	struct lb4_service *svc;
	struct lb4_key key = {
		.address	= ctx->user_ip4,
		.dport		= ctx_dst_port(ctx),
	}, orig_key = key;
	struct lb4_service *backend_slot;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;
#ifdef ENABLE_L7_LB
	struct lb4_backend l7backend;
#endif

	if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)
		return -ENXIO;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	/* In case a direct match fails, we try to look-up surrogate
	 * service entries via wildcarded lookup for NodePort and
	 * HostPort services.
	 */
	svc = lb4_lookup_service(&key, true);
	if (!svc)
		svc = sock4_wildcard_lookup_full(&key, in_hostns);
	if (!svc)
		return -ENXIO;

	/* Do not perform service translation for external IPs
	 * that are not a local address because we don't want
	 * a k8s service to easily do MITM attacks for a public
	 * IP address. But do the service translation if the IP
	 * is from the host.
	 */
	if (sock4_skip_xlate(svc, orig_key.address))
		return -EPERM;

#ifdef ENABLE_L7_LB
	/* Do not perform service translation at socker layer for
	 * services with L7 load balancing as we need to postpone
	 * policy enforcement to take place after l7 load balancer and
	 * we can't currently do that from the socket layer.
	 */
	if (lb4_svc_is_l7loadbalancer(svc)) {
		/* TC level eBPF datapath does not handle node local traffic,
		 * but we need to redirect for L7 LB also in that case.
		 */
		if (is_defined(BPF_HAVE_NETNS_COOKIE) && in_hostns) {
			/* Use the L7 LB proxy port as a backend. Normally this
			 * would cause policy enforcement to be done before the
			 * L7 LB (which should not be done), but in this case
			 * (node-local nodeport) there is no policy enforcement
			 * anyway.
			 */
			l7backend.address = bpf_htonl(0x7f000001);
			l7backend.port = (__be16)svc->l7_lb_proxy_port;
			l7backend.proto = 0;
			l7backend.flags = 0;
			backend = &l7backend;
			goto out;
		}
		/* Let the TC level eBPF datapath redirect to L7 LB. */
		return 0;
	}
#endif /* ENABLE_L7_LB */

	if (lb4_svc_is_affinity(svc)) {
		/* Note, for newly created affinity entries there is a
		 * small race window. Two processes on two different
		 * CPUs but the same netns may select different backends
		 * for the same service:port. lb4_update_affinity_by_netns()
		 * below would then override the first created one if it
		 * didn't make it into the lookup yet for the other CPU.
		 */
		backend_id = lb4_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;

		if (backend_id != 0) {
			backend = __lb4_lookup_backend(backend_id);
			if (!backend)
				/* Backend from the session affinity no longer
				 * exists, thus select a new one. Also, remove
				 * the affinity, so that if the svc doesn't have
				 * any backend, a subsequent request to the svc
				 * doesn't hit the reselection again.
				 */
				backend_id = 0;
		}
	}

	if (backend_id == 0) {
		backend_from_affinity = false;

		key.backend_slot = (sock_select_slot(ctx_full) % svc->count) + 1;
		backend_slot = __lb4_lookup_backend_slot(&key);
		if (!backend_slot) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
			return -ENOENT;
		}

		backend_id = backend_slot->backend_id;
		backend = __lb4_lookup_backend(backend_id);
	}

	if (!backend) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -ENOENT;
	}

	if (lb4_svc_is_localredirect(svc) &&
	    sock4_skip_xlate_if_same_netns(ctx_full, backend))
		return -ENXIO;

	if (lb4_svc_is_affinity(svc) && !backend_from_affinity)
		lb4_update_affinity_by_netns(svc, &id, backend_id);
#ifdef ENABLE_L7_LB
out:
#endif
	if (sock4_update_revnat(ctx_full, backend, &orig_key,
				svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx->user_ip4 = backend->address;
	ctx_set_port(ctx, backend->port);

	return 0;
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
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_socket_cookie": [
      {
        "opVar": "#ifdef ENABLE_HEALTH_CHECK\t__sock_cookie key ",
        "inpVar": [
          " ctx"
        ]
      }
    ],
    "map_lookup_elem": [
      {
        "opVar": "\tif (!lb_skip_l4_dnat())\t\tval ",
        "inpVar": [
          " &LB4_HEALTH_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 460,
  "endLine": 476,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock4_health_fwd",
  "updateMaps": [],
  "readMaps": [
    " LB4_HEALTH_MAP"
  ],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "get_socket_cookie",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "sk_skb",
    "cgroup_skb",
    "sock_ops"
  ],
  "source": [
    "static __always_inline int __sock4_health_fwd (struct bpf_sock_addr * ctx __maybe_unused)\n",
    "{\n",
    "    int ret = lb_skip_l4_dnat () ? SYS_PROCEED : SYS_REJECT;\n",
    "\n",
    "#ifdef ENABLE_HEALTH_CHECK\n",
    "    __sock_cookie key = get_socket_cookie (ctx);\n",
    "    struct lb4_health *val = NULL;\n",
    "    if (!lb_skip_l4_dnat ())\n",
    "        val = map_lookup_elem (&LB4_HEALTH_MAP, &key);\n",
    "    if (val) {\n",
    "        ctx_set_port (ctx, val->peer.port);\n",
    "        ret = SYS_PROCEED;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HEALTH_CHECK */\n",
    "    return ret;\n",
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
static __always_inline int
__sock4_health_fwd(struct bpf_sock_addr *ctx __maybe_unused)
{
	int ret = lb_skip_l4_dnat() ? SYS_PROCEED : SYS_REJECT;
#ifdef ENABLE_HEALTH_CHECK
	__sock_cookie key = get_socket_cookie(ctx);
	struct lb4_health *val = NULL;

	if (!lb_skip_l4_dnat())
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
	if (val) {
		ctx_set_port(ctx, val->peer.port);
		ret = SYS_PROCEED;
	}
#endif /* ENABLE_HEALTH_CHECK */
	return ret;
}

__section("cgroup/connect4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 479,
  "endLine": 486,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_connect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock4_connect (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    if (sock_is_health_check (ctx))\n",
    "        return __sock4_health_fwd (ctx);\n",
    "    __sock4_xlate_fwd (ctx, ctx, false);\n",
    "    return SYS_PROCEED;\n",
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
int sock4_connect(struct bpf_sock_addr *ctx)
{
	if (sock_is_health_check(ctx))
		return __sock4_health_fwd(ctx);

	__sock4_xlate_fwd(ctx, ctx, false);
	return SYS_PROCEED;
}

#ifdef ENABLE_NODEPORT
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 489,
  "endLine": 520,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock4_post_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock *ctx",
    " struct bpf_sock *ctx_full"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int __sock4_post_bind (struct bpf_sock *ctx, struct bpf_sock *ctx_full)\n",
    "{\n",
    "    struct lb4_service *svc;\n",
    "    struct lb4_key key = {\n",
    "        .address = ctx->src_ip4,\n",
    "        .dport = ctx_src_port (ctx),}\n",
    "    ;\n",
    "    if (!sock_proto_enabled (ctx->protocol) || !ctx_in_hostns (ctx_full, NULL))\n",
    "        return 0;\n",
    "    svc = lb4_lookup_service (& key, true);\n",
    "    if (!svc)\n",
    "        svc = sock4_wildcard_lookup (&key, false, false, true);\n",
    "    if (svc && (lb4_svc_is_nodeport (svc) || lb4_svc_is_external_ip (svc) || lb4_svc_is_loadbalancer (svc)))\n",
    "        return -EADDRINUSE;\n",
    "    return 0;\n",
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
static __always_inline int __sock4_post_bind(struct bpf_sock *ctx,
					     struct bpf_sock *ctx_full)
{
	struct lb4_service *svc;
	struct lb4_key key = {
		.address	= ctx->src_ip4,
		.dport		= ctx_src_port(ctx),
	};

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx_full, NULL))
		return 0;

	svc = lb4_lookup_service(&key, true);
	if (!svc)
		/* Perform a wildcard lookup for the case where the caller
		 * tries to bind to loopback or an address with host identity
		 * (without remote hosts).
		 */
		svc = sock4_wildcard_lookup(&key, false, false, true);

	/* If the sockaddr of this socket overlaps with a NodePort,
	 * LoadBalancer or ExternalIP service. We must reject this
	 * bind() call to avoid accidentally hijacking its traffic.
	 */
	if (svc && (lb4_svc_is_nodeport(svc) ||
		    lb4_svc_is_external_ip(svc) ||
		    lb4_svc_is_loadbalancer(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("cgroup/post_bind4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tif __sock4_post_ctx",
          " ctx < 0\t\treturn SYS_REJECT"
        ]
      }
    ]
  },
  "startLine": 523,
  "endLine": 529,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_post_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock *ctx"
  ],
  "output": "int",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "int sock4_post_bind (struct bpf_sock *ctx)\n",
    "{\n",
    "    if (__sock4_post_bind (ctx, ctx) < 0)\n",
    "        return SYS_REJECT;\n",
    "    return SYS_PROCEED;\n",
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
int sock4_post_bind(struct bpf_sock *ctx)
{
	if (__sock4_post_bind(ctx, ctx) < 0)
		return SYS_REJECT;

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 533,
  "endLine": 537,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_auto_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline void sock4_auto_bind (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    ctx->user_ip4 = 0;\n",
    "    ctx_set_port (ctx, 0);\n",
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
static __always_inline void sock4_auto_bind(struct bpf_sock_addr *ctx)
{
	ctx->user_ip4 = 0;
	ctx_set_port(ctx, 0);
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
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_socket_cookie": [
      {
        "opVar": "\t\t__sock_cookie key ",
        "inpVar": [
          " ctx_full"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "\tret ",
        "inpVar": [
          " &LB4_HEALTH_MAP",
          " &key",
          " &val",
          " 0"
        ]
      }
    ],
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tif !ret\t\tsock4_auto_ctx"
        ]
      }
    ]
  },
  "startLine": 539,
  "endLine": 559,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock4_pre_bind",
  "updateMaps": [
    "  LB4_HEALTH_MAP"
  ],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " struct bpf_sock_addr *ctx_full"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_update_elem",
    "bind",
    "get_socket_cookie"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int __sock4_pre_bind (struct bpf_sock_addr *ctx, struct bpf_sock_addr *ctx_full)\n",
    "{\n",
    "    __sock_cookie key = get_socket_cookie (ctx_full);\n",
    "    struct lb4_health val = {\n",
    "        .peer = {\n",
    "            .address = ctx->user_ip4,\n",
    "            .port = ctx_dst_port (ctx),\n",
    "            .proto = (__u8) ctx->protocol,},}\n",
    "    ;\n",
    "    int ret;\n",
    "    ret = map_update_elem (& LB4_HEALTH_MAP, & key, & val, 0);\n",
    "    if (!ret)\n",
    "        sock4_auto_bind (ctx);\n",
    "    return ret;\n",
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
static __always_inline int __sock4_pre_bind(struct bpf_sock_addr *ctx,
					    struct bpf_sock_addr *ctx_full)
{
	/* Code compiled in here guarantees that get_socket_cookie() is
	 * available and unique on underlying kernel.
	 */
	__sock_cookie key = get_socket_cookie(ctx_full);
	struct lb4_health val = {
		.peer = {
			.address	= ctx->user_ip4,
			.port		= ctx_dst_port(ctx),
			.proto		= (__u8)ctx->protocol,
		},
	};
	int ret;

	ret = map_update_elem(&LB4_HEALTH_MAP, &key, &val, 0);
	if (!ret)
		sock4_auto_bind(ctx);
	return ret;
}

__section("cgroup/bind4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "\tif (sock_is_health_check(ctx) &&\t    __sock4_pre_bind(ctx, ctx))\t\tret ",
        "inpVar": [
          " SYS_REJECT"
        ]
      }
    ]
  },
  "startLine": 562,
  "endLine": 573,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_pre_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "int",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "int sock4_pre_bind (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    int ret = SYS_PROCEED;\n",
    "    if (!sock_proto_enabled (ctx->protocol) || !ctx_in_hostns (ctx, NULL))\n",
    "        return ret;\n",
    "    if (sock_is_health_check (ctx) && __sock4_pre_bind (ctx, ctx))\n",
    "        ret = SYS_REJECT;\n",
    "    return ret;\n",
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
int sock4_pre_bind(struct bpf_sock_addr *ctx)
{
	int ret = SYS_PROCEED;

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return ret;
	if (sock_is_health_check(ctx) &&
	    __sock4_pre_bind(ctx, ctx))
		ret = SYS_REJECT;
	return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

#if defined(ENABLE_SOCKET_LB_UDP) || defined(ENABLE_SOCKET_LB_PEER)
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\tval ",
        "inpVar": [
          " &LB4_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ],
    "map_delete_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t&LB4_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 577,
  "endLine": 611,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock4_xlate_rev",
  "updateMaps": [
    " LB4_REVERSE_NAT_SK_MAP"
  ],
  "readMaps": [
    "  LB4_REVERSE_NAT_SK_MAP"
  ],
  "input": [
    "struct bpf_sock_addr *ctx",
    " struct bpf_sock_addr *ctx_full"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_delete_elem",
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
    "sk_reuseport",
    "cgroup_sysctl",
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
    "static __always_inline int __sock4_xlate_rev (struct bpf_sock_addr *ctx, struct bpf_sock_addr *ctx_full)\n",
    "{\n",
    "    struct ipv4_revnat_entry *val;\n",
    "    struct ipv4_revnat_tuple key = {\n",
    "        .cookie = sock_local_cookie (ctx_full),\n",
    "        .address = ctx->user_ip4,\n",
    "        .port = ctx_dst_port (ctx),}\n",
    "    ;\n",
    "    val = map_lookup_elem (& LB4_REVERSE_NAT_SK_MAP, & key);\n",
    "    if (val) {\n",
    "        struct lb4_service *svc;\n",
    "        struct lb4_key svc_key = {\n",
    "            .address = val->address,\n",
    "            .dport = val->port,}\n",
    "        ;\n",
    "        svc = lb4_lookup_service (& svc_key, true);\n",
    "        if (!svc)\n",
    "            svc = sock4_wildcard_lookup_full (&svc_key, ctx_in_hostns (ctx_full, NULL));\n",
    "        if (!svc || svc->rev_nat_index != val->rev_nat_index) {\n",
    "            map_delete_elem (&LB4_REVERSE_NAT_SK_MAP, &key);\n",
    "            update_metrics (0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);\n",
    "            return -ENOENT;\n",
    "        }\n",
    "        ctx->user_ip4 = val->address;\n",
    "        ctx_set_port (ctx, val->port);\n",
    "        return 0;\n",
    "    }\n",
    "    return -ENXIO;\n",
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
static __always_inline int __sock4_xlate_rev(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full)
{
	struct ipv4_revnat_entry *val;
	struct ipv4_revnat_tuple key = {
		.cookie		= sock_local_cookie(ctx_full),
		.address	= ctx->user_ip4,
		.port		= ctx_dst_port(ctx),
	};

	val = map_lookup_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
	if (val) {
		struct lb4_service *svc;
		struct lb4_key svc_key = {
			.address	= val->address,
			.dport		= val->port,
		};

		svc = lb4_lookup_service(&svc_key, true);
		if (!svc)
			svc = sock4_wildcard_lookup_full(&svc_key,
						ctx_in_hostns(ctx_full, NULL));
		if (!svc || svc->rev_nat_index != val->rev_nat_index) {
			map_delete_elem(&LB4_REVERSE_NAT_SK_MAP, &key);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx->user_ip4 = val->address;
		ctx_set_port(ctx, val->port);
		return 0;
	}

	return -ENXIO;
}

__section("cgroup/sendmsg4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 614,
  "endLine": 618,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_sendmsg",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock4_sendmsg (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock4_xlate_fwd (ctx, ctx, true);\n",
    "    return SYS_PROCEED;\n",
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
int sock4_sendmsg(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_fwd(ctx, ctx, true);
	return SYS_PROCEED;
}

__section("cgroup/recvmsg4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 621,
  "endLine": 625,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_recvmsg",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock4_recvmsg (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock4_xlate_rev (ctx, ctx);\n",
    "    return SYS_PROCEED;\n",
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
int sock4_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}

__section("cgroup/getpeername4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 628,
  "endLine": 632,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock4_getpeername",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock4_getpeername (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock4_xlate_rev (ctx, ctx);\n",
    "    return SYS_PROCEED;\n",
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
int sock4_getpeername(struct bpf_sock_addr *ctx)
{
	__sock4_xlate_rev(ctx, ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_UDP || ENABLE_SOCKET_LB_PEER */
#endif /* ENABLE_IPV4 */

#if defined(ENABLE_IPV6) || defined(ENABLE_IPV4)
#ifdef ENABLE_IPV6
#if defined(ENABLE_SOCKET_LB_UDP) || defined(ENABLE_SOCKET_LB_PEER)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_revnat_tuple);
	__type(value, struct ipv6_revnat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LB6_REVERSE_NAT_SK_MAP_SIZE);
} LB6_REVERSE_NAT_SK_MAP __section_maps_btf;

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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\ttmp ",
        "inpVar": [
          " &LB6_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "\tif (!tmp || memcmp(tmp, &val, sizeof(val)))\t\tret ",
        "inpVar": [
          " &LB6_REVERSE_NAT_SK_MAP",
          " &key",
          "\t\t\t\t      &val",
          " 0"
        ]
      }
    ]
  },
  "startLine": 647,
  "endLine": 669,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_update_revnat",
  "updateMaps": [
    " LB6_REVERSE_NAT_SK_MAP"
  ],
  "readMaps": [
    "  LB6_REVERSE_NAT_SK_MAP"
  ],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const struct lb6_backend *backend",
    " const struct lb6_key *orig_key",
    " __u16 rev_nat_index"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_update_elem",
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
    "sk_reuseport",
    "cgroup_sysctl",
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
    "static __always_inline int sock6_update_revnat (struct bpf_sock_addr *ctx, const struct lb6_backend *backend, const struct lb6_key *orig_key, __u16 rev_nat_index)\n",
    "{\n",
    "    struct ipv6_revnat_entry val = {}, *tmp;\n",
    "    struct ipv6_revnat_tuple key = {}\n",
    "    ;\n",
    "    int ret = 0;\n",
    "    key.cookie = sock_local_cookie (ctx);\n",
    "    key.address = backend->address;\n",
    "    key.port = backend->port;\n",
    "    val.address = orig_key->address;\n",
    "    val.port = orig_key->dport;\n",
    "    val.rev_nat_index = rev_nat_index;\n",
    "    tmp = map_lookup_elem (& LB6_REVERSE_NAT_SK_MAP, & key);\n",
    "    if (!tmp || memcmp (tmp, &val, sizeof (val)))\n",
    "        ret = map_update_elem (&LB6_REVERSE_NAT_SK_MAP, &key, &val, 0);\n",
    "    return ret;\n",
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
static __always_inline int sock6_update_revnat(struct bpf_sock_addr *ctx,
					       const struct lb6_backend *backend,
					       const struct lb6_key *orig_key,
					       __u16 rev_nat_index)
{
	struct ipv6_revnat_entry val = {}, *tmp;
	struct ipv6_revnat_tuple key = {};
	int ret = 0;

	key.cookie = sock_local_cookie(ctx);
	key.address = backend->address;
	key.port = backend->port;

	val.address = orig_key->address;
	val.port = orig_key->dport;
	val.rev_nat_index = rev_nat_index;

	tmp = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
	if (!tmp || memcmp(tmp, &val, sizeof(val)))
		ret = map_update_elem(&LB6_REVERSE_NAT_SK_MAP, &key,
				      &val, 0);
	return ret;
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 671,
  "endLine": 678,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_update_revnat",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused",
    " struct lb6_backend * backend __maybe_unused",
    " struct lb6_key * orig_key __maybe_unused",
    " __u16 rev_nat_index __maybe_unused"
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
    "static __always_inline int sock6_update_revnat (struct bpf_sock_addr * ctx __maybe_unused, struct lb6_backend * backend __maybe_unused, struct lb6_key * orig_key __maybe_unused, __u16 rev_nat_index __maybe_unused)\n",
    "{\n",
    "    return 0;\n",
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
static __always_inline
int sock6_update_revnat(struct bpf_sock_addr *ctx __maybe_unused,
			struct lb6_backend *backend __maybe_unused,
			struct lb6_key *orig_key __maybe_unused,
			__u16 rev_nat_index __maybe_unused)
{
	return 0;
}
#endif /* ENABLE_SOCKET_LB_UDP || ENABLE_SOCKET_LB_PEER */
#endif /* ENABLE_IPV6 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 682,
  "endLine": 693,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_get_v6_address",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock_addr *ctx",
    " union v6addr *addr"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void ctx_get_v6_address (const struct bpf_sock_addr *ctx, union v6addr *addr)\n",
    "{\n",
    "    addr->p1 = ctx->user_ip6[0];\n",
    "    barrier ();\n",
    "    addr->p2 = ctx->user_ip6[1];\n",
    "    barrier ();\n",
    "    addr->p3 = ctx->user_ip6[2];\n",
    "    barrier ();\n",
    "    addr->p4 = ctx->user_ip6[3];\n",
    "    barrier ();\n",
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
static __always_inline void ctx_get_v6_address(const struct bpf_sock_addr *ctx,
					       union v6addr *addr)
{
	addr->p1 = ctx->user_ip6[0];
	barrier();
	addr->p2 = ctx->user_ip6[1];
	barrier();
	addr->p3 = ctx->user_ip6[2];
	barrier();
	addr->p4 = ctx->user_ip6[3];
	barrier();
}

#ifdef ENABLE_NODEPORT
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 696,
  "endLine": 707,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_get_v6_src_address",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock *ctx",
    " union v6addr *addr"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void ctx_get_v6_src_address (const struct bpf_sock *ctx, union v6addr *addr)\n",
    "{\n",
    "    addr->p1 = ctx->src_ip6[0];\n",
    "    barrier ();\n",
    "    addr->p2 = ctx->src_ip6[1];\n",
    "    barrier ();\n",
    "    addr->p3 = ctx->src_ip6[2];\n",
    "    barrier ();\n",
    "    addr->p4 = ctx->src_ip6[3];\n",
    "    barrier ();\n",
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
static __always_inline void ctx_get_v6_src_address(const struct bpf_sock *ctx,
						   union v6addr *addr)
{
	addr->p1 = ctx->src_ip6[0];
	barrier();
	addr->p2 = ctx->src_ip6[1];
	barrier();
	addr->p3 = ctx->src_ip6[2];
	barrier();
	addr->p4 = ctx->src_ip6[3];
	barrier();
}
#endif /* ENABLE_NODEPORT */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 710,
  "endLine": 721,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "ctx_set_v6_address",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const union v6addr *addr"
  ],
  "output": "static__always_inlinevoid",
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
    "static __always_inline void ctx_set_v6_address (struct bpf_sock_addr *ctx, const union v6addr *addr)\n",
    "{\n",
    "    ctx->user_ip6[0] = addr->p1;\n",
    "    barrier ();\n",
    "    ctx->user_ip6[1] = addr->p2;\n",
    "    barrier ();\n",
    "    ctx->user_ip6[2] = addr->p3;\n",
    "    barrier ();\n",
    "    ctx->user_ip6[3] = addr->p4;\n",
    "    barrier ();\n",
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
static __always_inline void ctx_set_v6_address(struct bpf_sock_addr *ctx,
					       const union v6addr *addr)
{
	ctx->user_ip6[0] = addr->p1;
	barrier();
	ctx->user_ip6[1] = addr->p2;
	barrier();
	ctx->user_ip6[2] = addr->p3;
	barrier();
	ctx->user_ip6[3] = addr->p4;
	barrier();
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 723,
  "endLine": 739,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_skip_xlate",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb6_service *svc",
    " const union v6addr *address"
  ],
  "output": "static__always_inline__maybe_unusedbool",
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
    "static __always_inline __maybe_unused bool sock6_skip_xlate (struct lb6_service *svc, const union v6addr *address)\n",
    "{\n",
    "    if (lb6_to_lb4_service (svc))\n",
    "        return true;\n",
    "    if (lb6_svc_is_external_ip (svc) || (lb6_svc_is_hostport (svc) && !is_v6_loopback (address))) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = ipcache_lookup6 (& IPCACHE_MAP, address, V6_CACHE_KEY_LEN);\n",
    "        if (info == NULL || info->sec_label != HOST_ID)\n",
    "            return true;\n",
    "    }\n",
    "    return false;\n",
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
static __always_inline __maybe_unused bool
sock6_skip_xlate(struct lb6_service *svc, const union v6addr *address)
{
	if (lb6_to_lb4_service(svc))
		return true;
	if (lb6_svc_is_external_ip(svc) ||
	    (lb6_svc_is_hostport(svc) && !is_v6_loopback(address))) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup6(&IPCACHE_MAP, address,
				       V6_CACHE_KEY_LEN);
		if (info == NULL || info->sec_label != HOST_ID)
			return true;
	}

	return false;
}

#ifdef ENABLE_NODEPORT
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 742,
  "endLine": 772,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "*sock6_wildcard_lookup",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb6_key * key __maybe_unused",
    " const bool include_remote_hosts __maybe_unused",
    " const bool inv_match __maybe_unused",
    " const bool in_hostns __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedstructlb6_service",
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
    "static __always_inline __maybe_unused struct lb6_service *sock6_wildcard_lookup (struct lb6_key * key __maybe_unused, const bool include_remote_hosts __maybe_unused, const bool inv_match __maybe_unused, const bool in_hostns __maybe_unused)\n",
    "{\n",
    "    struct remote_endpoint_info *info;\n",
    "    __u16 service_port;\n",
    "    service_port = bpf_ntohs (key -> dport);\n",
    "    if ((service_port < NODEPORT_PORT_MIN || service_port > NODEPORT_PORT_MAX) ^ inv_match)\n",
    "        return NULL;\n",
    "    if (in_hostns && is_v6_loopback (&key->address))\n",
    "        goto wildcard_lookup;\n",
    "    info = ipcache_lookup6 (& IPCACHE_MAP, & key -> address, V6_CACHE_KEY_LEN);\n",
    "    if (info != NULL && (info->sec_label == HOST_ID || (include_remote_hosts && identity_is_remote_node (info->sec_label))))\n",
    "        goto wildcard_lookup;\n",
    "    return NULL;\n",
    "wildcard_lookup :\n",
    "    memset (&key->address, 0, sizeof (key->address));\n",
    "    return lb6_lookup_service (key, true);\n",
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
static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup(struct lb6_key *key __maybe_unused,
		      const bool include_remote_hosts __maybe_unused,
		      const bool inv_match __maybe_unused,
		      const bool in_hostns __maybe_unused)
{
	struct remote_endpoint_info *info;
	__u16 service_port;

	service_port = bpf_ntohs(key->dport);
	if ((service_port < NODEPORT_PORT_MIN ||
	     service_port > NODEPORT_PORT_MAX) ^ inv_match)
		return NULL;

	/* When connecting to node port services in our cluster that
	 * have either {REMOTE_NODE,HOST}_ID or loopback address, we
	 * do a wild-card lookup with IP of 0.
	 */
	if (in_hostns && is_v6_loopback(&key->address))
		goto wildcard_lookup;

	info = ipcache_lookup6(&IPCACHE_MAP, &key->address, V6_CACHE_KEY_LEN);
	if (info != NULL && (info->sec_label == HOST_ID ||
	    (include_remote_hosts && identity_is_remote_node(info->sec_label))))
		goto wildcard_lookup;

	return NULL;
wildcard_lookup:
	memset(&key->address, 0, sizeof(key->address));
	return lb6_lookup_service(key, true);
}
#endif /* ENABLE_NODEPORT */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 775,
  "endLine": 793,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "*sock6_wildcard_lookup_full",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb6_key * key __maybe_unused",
    " const bool in_hostns __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedstructlb6_service",
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
    "static __always_inline __maybe_unused struct lb6_service *sock6_wildcard_lookup_full (struct lb6_key * key __maybe_unused, const bool in_hostns __maybe_unused)\n",
    "{\n",
    "    struct lb6_service *svc = NULL;\n",
    "\n",
    "#ifdef ENABLE_NODEPORT\n",
    "    svc = sock6_wildcard_lookup (key, true, false, in_hostns);\n",
    "    if (svc && !lb6_svc_is_nodeport (svc))\n",
    "        svc = NULL;\n",
    "    if (!svc) {\n",
    "        svc = sock6_wildcard_lookup (key, false, true, in_hostns);\n",
    "        if (svc && !lb6_svc_is_hostport (svc))\n",
    "            svc = NULL;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_NODEPORT */\n",
    "    return svc;\n",
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
static __always_inline __maybe_unused struct lb6_service *
sock6_wildcard_lookup_full(struct lb6_key *key __maybe_unused,
			   const bool in_hostns __maybe_unused)
{
	struct lb6_service *svc = NULL;

#ifdef ENABLE_NODEPORT
	svc = sock6_wildcard_lookup(key, true, false, in_hostns);
	if (svc && !lb6_svc_is_nodeport(svc))
		svc = NULL;
	if (!svc) {
		svc = sock6_wildcard_lookup(key, false, true,
					    in_hostns);
		if (svc && !lb6_svc_is_hostport(svc))
			svc = NULL;
	}
#endif /* ENABLE_NODEPORT */
	return svc;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 795,
  "endLine": 824,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_xlate_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused",
    " const bool udp_only __maybe_unused"
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
    "static __always_inline int sock6_xlate_v4_in_v6 (struct bpf_sock_addr * ctx __maybe_unused, const bool udp_only __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    struct bpf_sock_addr fake_ctx;\n",
    "    union v6addr addr6;\n",
    "    int ret;\n",
    "    ctx_get_v6_address (ctx, &addr6);\n",
    "    if (!is_v4_in_v6 (&addr6))\n",
    "        return -ENXIO;\n",
    "    memset (&fake_ctx, 0, sizeof (fake_ctx));\n",
    "    fake_ctx.protocol = ctx->protocol;\n",
    "    fake_ctx.user_ip4 = addr6.p4;\n",
    "    fake_ctx.user_port = ctx_dst_port (ctx);\n",
    "    ret = __sock4_xlate_fwd (& fake_ctx, ctx, udp_only);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    build_v4_in_v6 (&addr6, fake_ctx.user_ip4);\n",
    "    ctx_set_v6_address (ctx, &addr6);\n",
    "    ctx_set_port (ctx, (__u16) fake_ctx.user_port);\n",
    "    return 0;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    return -ENXIO;\n",
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
static __always_inline
int sock6_xlate_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused,
			 const bool udp_only __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return -ENXIO;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_xlate_fwd(&fake_ctx, ctx, udp_only);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
}

#ifdef ENABLE_NODEPORT
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "sock6_post__v4_in_v6struct bpf_sock *ctx __maybe_unused"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn __sock4_post_&fake_ctx",
          " ctx"
        ]
      }
    ]
  },
  "startLine": 827,
  "endLine": 846,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_post_bind_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int sock6_post_bind_v4_in_v6 (struct bpf_sock * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    struct bpf_sock fake_ctx;\n",
    "    union v6addr addr6;\n",
    "    ctx_get_v6_src_address (ctx, &addr6);\n",
    "    if (!is_v4_in_v6 (&addr6))\n",
    "        return 0;\n",
    "    memset (&fake_ctx, 0, sizeof (fake_ctx));\n",
    "    fake_ctx.protocol = ctx->protocol;\n",
    "    fake_ctx.src_ip4 = addr6.p4;\n",
    "    fake_ctx.src_port = ctx->src_port;\n",
    "    return __sock4_post_bind (&fake_ctx, ctx);\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    return 0;\n",
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
static __always_inline int
sock6_post_bind_v4_in_v6(struct bpf_sock *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock fake_ctx;
	union v6addr addr6;

	ctx_get_v6_src_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return 0;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol = ctx->protocol;
	fake_ctx.src_ip4  = addr6.p4;
	fake_ctx.src_port = ctx->src_port;

	return __sock4_post_bind(&fake_ctx, ctx);
#endif /* ENABLE_IPV4 */
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tif !svc\t\t\treturn sock6_post__v4_in_v6ctx"
        ]
      }
    ]
  },
  "startLine": 848,
  "endLine": 874,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock6_post_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int __sock6_post_bind (struct bpf_sock *ctx)\n",
    "{\n",
    "    struct lb6_service *svc;\n",
    "    struct lb6_key key = {\n",
    "        .dport = ctx_src_port (ctx),}\n",
    "    ;\n",
    "    if (!sock_proto_enabled (ctx->protocol) || !ctx_in_hostns (ctx, NULL))\n",
    "        return 0;\n",
    "    ctx_get_v6_src_address (ctx, &key.address);\n",
    "    svc = lb6_lookup_service (& key, true);\n",
    "    if (!svc) {\n",
    "        svc = sock6_wildcard_lookup (& key, false, false, true);\n",
    "        if (!svc)\n",
    "            return sock6_post_bind_v4_in_v6 (ctx);\n",
    "    }\n",
    "    if (svc && (lb6_svc_is_nodeport (svc) || lb6_svc_is_external_ip (svc) || lb6_svc_is_loadbalancer (svc)))\n",
    "        return -EADDRINUSE;\n",
    "    return 0;\n",
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
static __always_inline int __sock6_post_bind(struct bpf_sock *ctx)
{
	struct lb6_service *svc;
	struct lb6_key key = {
		.dport		= ctx_src_port(ctx),
	};

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return 0;

	ctx_get_v6_src_address(ctx, &key.address);

	svc = lb6_lookup_service(&key, true);
	if (!svc) {
		svc = sock6_wildcard_lookup(&key, false, false, true);
		if (!svc)
			return sock6_post_bind_v4_in_v6(ctx);
	}

	if (svc && (lb6_svc_is_nodeport(svc) ||
		    lb6_svc_is_external_ip(svc) ||
		    lb6_svc_is_loadbalancer(svc)))
		return -EADDRINUSE;

	return 0;
}

__section("cgroup/post_bind6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tif __sock6_post_ctx < 0\t\treturn SYS_REJECT"
        ]
      }
    ]
  },
  "startLine": 877,
  "endLine": 883,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_post_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock *ctx"
  ],
  "output": "int",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "int sock6_post_bind (struct bpf_sock *ctx)\n",
    "{\n",
    "    if (__sock6_post_bind (ctx) < 0)\n",
    "        return SYS_REJECT;\n",
    "    return SYS_PROCEED;\n",
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
int sock6_post_bind(struct bpf_sock *ctx)
{
	if (__sock6_post_bind(ctx) < 0)
		return SYS_REJECT;

	return SYS_PROCEED;
}
#endif /* ENABLE_NODEPORT */

#ifdef ENABLE_HEALTH_CHECK
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "sock6_pre__v4_in_v6struct bpf_sock_addr *ctx __maybe_unused"
        ]
      },
      {
        "opVar": "\tret ",
        "inpVar": [
          " __sock4_pre_&fake_ctx",
          " ctx"
        ]
      }
    ]
  },
  "startLine": 887,
  "endLine": 911,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_pre_bind_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int sock6_pre_bind_v4_in_v6 (struct bpf_sock_addr * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    struct bpf_sock_addr fake_ctx;\n",
    "    union v6addr addr6;\n",
    "    int ret;\n",
    "    ctx_get_v6_address (ctx, &addr6);\n",
    "    memset (&fake_ctx, 0, sizeof (fake_ctx));\n",
    "    fake_ctx.protocol = ctx->protocol;\n",
    "    fake_ctx.user_ip4 = addr6.p4;\n",
    "    fake_ctx.user_port = ctx_dst_port (ctx);\n",
    "    ret = __sock4_pre_bind (& fake_ctx, ctx);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    build_v4_in_v6 (&addr6, fake_ctx.user_ip4);\n",
    "    ctx_set_v6_address (ctx, &addr6);\n",
    "    ctx_set_port (ctx, (__u16) fake_ctx.user_port);\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    return 0;\n",
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
static __always_inline int
sock6_pre_bind_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_pre_bind(&fake_ctx, ctx);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);
#endif /* ENABLE_IPV4 */
	return 0;
}

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 914,
  "endLine": 920,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_auto_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline void sock6_auto_bind (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    union v6addr zero = {}\n",
    "    ;\n",
    "    ctx_set_v6_address (ctx, &zero);\n",
    "    ctx_set_port (ctx, 0);\n",
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
static __always_inline void sock6_auto_bind(struct bpf_sock_addr *ctx)
{
	union v6addr zero = {};

	ctx_set_v6_address(ctx, &zero);
	ctx_set_port(ctx, 0);
}
#endif

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
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tif is_v4_in_v6&val.peer.address\t\treturn sock6_pre__v4_in_v6ctx"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\tif !ret\t\tsock6_auto_ctx"
        ]
      }
    ],
    "get_socket_cookie": [
      {
        "opVar": "#ifdef ENABLE_IPV6\tkey ",
        "inpVar": [
          " ctx"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "\tret ",
        "inpVar": [
          " &LB6_HEALTH_MAP",
          " &key",
          " &val",
          " 0"
        ]
      }
    ]
  },
  "startLine": 923,
  "endLine": 944,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock6_pre_bind",
  "updateMaps": [
    "  LB6_HEALTH_MAP"
  ],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_update_elem",
    "bind",
    "get_socket_cookie"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "static __always_inline int __sock6_pre_bind (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock_cookie key __maybe_unused;\n",
    "    struct lb6_health val = {\n",
    "        .peer = {\n",
    "            .port = ctx_dst_port (ctx),\n",
    "            .proto = (__u8) ctx->protocol,},}\n",
    "    ;\n",
    "    int ret = 0;\n",
    "    ctx_get_v6_address (ctx, &val.peer.address);\n",
    "    if (is_v4_in_v6 (&val.peer.address))\n",
    "        return sock6_pre_bind_v4_in_v6 (ctx);\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    key = get_socket_cookie (ctx);\n",
    "    ret = map_update_elem (& LB6_HEALTH_MAP, & key, & val, 0);\n",
    "    if (!ret)\n",
    "        sock6_auto_bind (ctx);\n",
    "\n",
    "#endif\n",
    "    return ret;\n",
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
static __always_inline int __sock6_pre_bind(struct bpf_sock_addr *ctx)
{
	__sock_cookie key __maybe_unused;
	struct lb6_health val = {
		.peer = {
			.port		= ctx_dst_port(ctx),
			.proto		= (__u8)ctx->protocol,
		},
	};
	int ret = 0;

	ctx_get_v6_address(ctx, &val.peer.address);
	if (is_v4_in_v6(&val.peer.address))
		return sock6_pre_bind_v4_in_v6(ctx);
#ifdef ENABLE_IPV6
	key = get_socket_cookie(ctx);
	ret = map_update_elem(&LB6_HEALTH_MAP, &key, &val, 0);
	if (!ret)
		sock6_auto_bind(ctx);
#endif
	return ret;
}

__section("cgroup/bind6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bind": [
      {
        "opVar": "\tif (sock_is_health_check(ctx) &&\t    __sock6_pre_bind(ctx))\t\tret ",
        "inpVar": [
          " SYS_REJECT"
        ]
      }
    ]
  },
  "startLine": 947,
  "endLine": 958,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_pre_bind",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "int",
  "helper": [
    "bind"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr"
  ],
  "source": [
    "int sock6_pre_bind (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    int ret = SYS_PROCEED;\n",
    "    if (!sock_proto_enabled (ctx->protocol) || !ctx_in_hostns (ctx, NULL))\n",
    "        return ret;\n",
    "    if (sock_is_health_check (ctx) && __sock6_pre_bind (ctx))\n",
    "        ret = SYS_REJECT;\n",
    "    return ret;\n",
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
int sock6_pre_bind(struct bpf_sock_addr *ctx)
{
	int ret = SYS_PROCEED;

	if (!sock_proto_enabled(ctx->protocol) ||
	    !ctx_in_hostns(ctx, NULL))
		return ret;
	if (sock_is_health_check(ctx) &&
	    __sock6_pre_bind(ctx))
		ret = SYS_REJECT;
	return ret;
}
#endif /* ENABLE_HEALTH_CHECK */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 961,
  "endLine": 1062,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock6_xlate_fwd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const bool udp_only"
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
    "static __always_inline int __sock6_xlate_fwd (struct bpf_sock_addr *ctx, const bool udp_only)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    union lb6_affinity_client_id id;\n",
    "    const bool in_hostns = ctx_in_hostns (ctx, & id.client_cookie);\n",
    "    struct lb6_backend *backend;\n",
    "    struct lb6_service *svc;\n",
    "    struct lb6_key key = {\n",
    "        .dport = ctx_dst_port (ctx),}, orig_key;\n",
    "    struct lb6_service *backend_slot;\n",
    "    bool backend_from_affinity = false;\n",
    "    __u32 backend_id = 0;\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    struct lb6_backend l7backend;\n",
    "\n",
    "#endif\n",
    "    if (is_defined (ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)\n",
    "        return -ENXIO;\n",
    "    if (!udp_only && !sock_proto_enabled (ctx->protocol))\n",
    "        return -ENOTSUP;\n",
    "    ctx_get_v6_address (ctx, &key.address);\n",
    "    memcpy (&orig_key, &key, sizeof (key));\n",
    "    svc = lb6_lookup_service (& key, true);\n",
    "    if (!svc)\n",
    "        svc = sock6_wildcard_lookup_full (&key, in_hostns);\n",
    "    if (!svc)\n",
    "        return sock6_xlate_v4_in_v6 (ctx, udp_only);\n",
    "    if (sock6_skip_xlate (svc, &orig_key.address))\n",
    "        return -EPERM;\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "    if (lb6_svc_is_l7loadbalancer (svc)) {\n",
    "        if (is_defined (BPF_HAVE_NETNS_COOKIE) && in_hostns) {\n",
    "            union v6addr loopback = {\n",
    "                .addr [15] = 1,}\n",
    "            ;\n",
    "            l7backend.address = loopback;\n",
    "            l7backend.port = (__be16) svc->l7_lb_proxy_port;\n",
    "            l7backend.proto = 0;\n",
    "            l7backend.flags = 0;\n",
    "            backend = &l7backend;\n",
    "            goto out;\n",
    "        }\n",
    "        return 0;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_L7_LB */\n",
    "    if (lb6_svc_is_affinity (svc)) {\n",
    "        backend_id = lb6_affinity_backend_id_by_netns (svc, & id);\n",
    "        backend_from_affinity = true;\n",
    "        if (backend_id != 0) {\n",
    "            backend = __lb6_lookup_backend (backend_id);\n",
    "            if (!backend)\n",
    "                backend_id = 0;\n",
    "        }\n",
    "    }\n",
    "    if (backend_id == 0) {\n",
    "        backend_from_affinity = false;\n",
    "        key.backend_slot = (sock_select_slot (ctx) % svc->count) + 1;\n",
    "        backend_slot = __lb6_lookup_backend_slot (& key);\n",
    "        if (!backend_slot) {\n",
    "            update_metrics (0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);\n",
    "            return -ENOENT;\n",
    "        }\n",
    "        backend_id = backend_slot->backend_id;\n",
    "        backend = __lb6_lookup_backend (backend_id);\n",
    "    }\n",
    "    if (!backend) {\n",
    "        update_metrics (0, METRIC_EGRESS, REASON_LB_NO_BACKEND);\n",
    "        return -ENOENT;\n",
    "    }\n",
    "    if (lb6_svc_is_affinity (svc) && !backend_from_affinity)\n",
    "        lb6_update_affinity_by_netns (svc, &id, backend_id);\n",
    "\n",
    "#ifdef ENABLE_L7_LB\n",
    "out :\n",
    "\n",
    "#endif\n",
    "    if (sock6_update_revnat (ctx, backend, &orig_key, svc->rev_nat_index) < 0) {\n",
    "        update_metrics (0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);\n",
    "        return -ENOMEM;\n",
    "    }\n",
    "    ctx_set_v6_address (ctx, &backend->address);\n",
    "    ctx_set_port (ctx, backend->port);\n",
    "    return 0;\n",
    "\n",
    "#else\n",
    "    return sock6_xlate_v4_in_v6 (ctx, udp_only);\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
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
static __always_inline int __sock6_xlate_fwd(struct bpf_sock_addr *ctx,
					     const bool udp_only)
{
#ifdef ENABLE_IPV6
	union lb6_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx, &id.client_cookie);
	struct lb6_backend *backend;
	struct lb6_service *svc;
	struct lb6_key key = {
		.dport		= ctx_dst_port(ctx),
	}, orig_key;
	struct lb6_service *backend_slot;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;
#ifdef ENABLE_L7_LB
	struct lb6_backend l7backend;
#endif

	if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)
		return -ENXIO;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	ctx_get_v6_address(ctx, &key.address);
	memcpy(&orig_key, &key, sizeof(key));

	svc = lb6_lookup_service(&key, true);
	if (!svc)
		svc = sock6_wildcard_lookup_full(&key, in_hostns);
	if (!svc)
		return sock6_xlate_v4_in_v6(ctx, udp_only);

	if (sock6_skip_xlate(svc, &orig_key.address))
		return -EPERM;

#ifdef ENABLE_L7_LB
	/* See __sock4_xlate_fwd for commentary. */
	if (lb6_svc_is_l7loadbalancer(svc)) {
		if (is_defined(BPF_HAVE_NETNS_COOKIE) && in_hostns) {
			union v6addr loopback = { .addr[15] = 1, };

			l7backend.address = loopback;
			l7backend.port = (__be16)svc->l7_lb_proxy_port;
			l7backend.proto = 0;
			l7backend.flags = 0;
			backend = &l7backend;
			goto out;
		}
		return 0;
	}
#endif /* ENABLE_L7_LB */

	if (lb6_svc_is_affinity(svc)) {
		backend_id = lb6_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;

		if (backend_id != 0) {
			backend = __lb6_lookup_backend(backend_id);
			if (!backend)
				backend_id = 0;
		}
	}

	if (backend_id == 0) {
		backend_from_affinity = false;

		key.backend_slot = (sock_select_slot(ctx) % svc->count) + 1;
		backend_slot = __lb6_lookup_backend_slot(&key);
		if (!backend_slot) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
			return -ENOENT;
		}

		backend_id = backend_slot->backend_id;
		backend = __lb6_lookup_backend(backend_id);
	}

	if (!backend) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -ENOENT;
	}

	if (lb6_svc_is_affinity(svc) && !backend_from_affinity)
		lb6_update_affinity_by_netns(svc, &id, backend_id);
#ifdef ENABLE_L7_LB
out:
#endif
	if (sock6_update_revnat(ctx, backend, &orig_key,
				svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx_set_v6_address(ctx, &backend->address);
	ctx_set_port(ctx, backend->port);

	return 0;
#else
	return sock6_xlate_v4_in_v6(ctx, udp_only);
#endif /* ENABLE_IPV6 */
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
          "Description": "Equivalent to get_socket_cookie() helper that accepts skb , but gets socket from struct sock_ops context. ",
          "Return": " A 8-byte long non-decreasing number.",
          "Function Name": "get_socket_cookie",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *ctx}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_socket_cookie": [
      {
        "opVar": "#ifdef ENABLE_IPV6\t\t__sock_cookie key ",
        "inpVar": [
          " ctx"
        ]
      }
    ],
    "map_lookup_elem": [
      {
        "opVar": "\t\tif (!lb_skip_l4_dnat())\t\t\tval ",
        "inpVar": [
          " &LB6_HEALTH_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 1064,
  "endLine": 1089,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock6_health_fwd",
  "updateMaps": [],
  "readMaps": [
    " LB6_HEALTH_MAP"
  ],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "get_socket_cookie",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "sk_skb",
    "cgroup_skb",
    "sock_ops"
  ],
  "source": [
    "static __always_inline int __sock6_health_fwd (struct bpf_sock_addr * ctx __maybe_unused)\n",
    "{\n",
    "    int ret = lb_skip_l4_dnat () ? SYS_PROCEED : SYS_REJECT;\n",
    "\n",
    "#ifdef ENABLE_HEALTH_CHECK\n",
    "    union v6addr addr6;\n",
    "    ctx_get_v6_address (ctx, &addr6);\n",
    "    if (is_v4_in_v6 (&addr6)) {\n",
    "        return __sock4_health_fwd (ctx);\n",
    "    }\n",
    "    else {\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "        __sock_cookie key = get_socket_cookie (ctx);\n",
    "        struct lb6_health *val = NULL;\n",
    "        if (!lb_skip_l4_dnat ())\n",
    "            val = map_lookup_elem (&LB6_HEALTH_MAP, &key);\n",
    "        if (val) {\n",
    "            ctx_set_port (ctx, val->peer.port);\n",
    "            ret = SYS_PROCEED;\n",
    "        }\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_HEALTH_CHECK */\n",
    "    return ret;\n",
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
static __always_inline int
__sock6_health_fwd(struct bpf_sock_addr *ctx __maybe_unused)
{
	int ret = lb_skip_l4_dnat() ? SYS_PROCEED : SYS_REJECT;
#ifdef ENABLE_HEALTH_CHECK
	union v6addr addr6;

	ctx_get_v6_address(ctx, &addr6);
	if (is_v4_in_v6(&addr6)) {
		return __sock4_health_fwd(ctx);
	} else {
#ifdef ENABLE_IPV6
		__sock_cookie key = get_socket_cookie(ctx);
		struct lb6_health *val = NULL;

		if (!lb_skip_l4_dnat())
			val = map_lookup_elem(&LB6_HEALTH_MAP, &key);
		if (val) {
			ctx_set_port(ctx, val->peer.port);
			ret = SYS_PROCEED;
		}
#endif /* ENABLE_IPV6 */
	}
#endif /* ENABLE_HEALTH_CHECK */
	return ret;
}

__section("cgroup/connect6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1092,
  "endLine": 1099,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_connect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock6_connect (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    if (sock_is_health_check (ctx))\n",
    "        return __sock6_health_fwd (ctx);\n",
    "    __sock6_xlate_fwd (ctx, false);\n",
    "    return SYS_PROCEED;\n",
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
int sock6_connect(struct bpf_sock_addr *ctx)
{
	if (sock_is_health_check(ctx))
		return __sock6_health_fwd(ctx);

	__sock6_xlate_fwd(ctx, false);
	return SYS_PROCEED;
}

#if defined(ENABLE_SOCKET_LB_UDP) || defined(ENABLE_SOCKET_LB_PEER)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1102,
  "endLine": 1130,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_xlate_rev_v4_in_v6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr * ctx __maybe_unused"
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
    "static __always_inline int sock6_xlate_rev_v4_in_v6 (struct bpf_sock_addr * ctx __maybe_unused)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "    struct bpf_sock_addr fake_ctx;\n",
    "    union v6addr addr6;\n",
    "    int ret;\n",
    "    ctx_get_v6_address (ctx, &addr6);\n",
    "    if (!is_v4_in_v6 (&addr6))\n",
    "        return -ENXIO;\n",
    "    memset (&fake_ctx, 0, sizeof (fake_ctx));\n",
    "    fake_ctx.protocol = ctx->protocol;\n",
    "    fake_ctx.user_ip4 = addr6.p4;\n",
    "    fake_ctx.user_port = ctx_dst_port (ctx);\n",
    "    ret = __sock4_xlate_rev (& fake_ctx, ctx);\n",
    "    if (ret < 0)\n",
    "        return ret;\n",
    "    build_v4_in_v6 (&addr6, fake_ctx.user_ip4);\n",
    "    ctx_set_v6_address (ctx, &addr6);\n",
    "    ctx_set_port (ctx, (__u16) fake_ctx.user_port);\n",
    "    return 0;\n",
    "\n",
    "#endif /* ENABLE_IPV4 */\n",
    "    return -ENXIO;\n",
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
static __always_inline int
sock6_xlate_rev_v4_in_v6(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_IPV4
	struct bpf_sock_addr fake_ctx;
	union v6addr addr6;
	int ret;

	ctx_get_v6_address(ctx, &addr6);
	if (!is_v4_in_v6(&addr6))
		return -ENXIO;

	memset(&fake_ctx, 0, sizeof(fake_ctx));
	fake_ctx.protocol  = ctx->protocol;
	fake_ctx.user_ip4  = addr6.p4;
	fake_ctx.user_port = ctx_dst_port(ctx);

	ret = __sock4_xlate_rev(&fake_ctx, ctx);
	if (ret < 0)
		return ret;

	build_v4_in_v6(&addr6, fake_ctx.user_ip4);
	ctx_set_v6_address(ctx, &addr6);
	ctx_set_port(ctx, (__u16)fake_ctx.user_port);

	return 0;
#endif /* ENABLE_IPV4 */
	return -ENXIO;
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\tval ",
        "inpVar": [
          " &LB6_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ],
    "map_delete_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\t&LB6_REVERSE_NAT_SK_MAP",
          " &key"
        ]
      }
    ]
  },
  "startLine": 1132,
  "endLine": 1167,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "__sock6_xlate_rev",
  "updateMaps": [
    " LB6_REVERSE_NAT_SK_MAP"
  ],
  "readMaps": [
    "  LB6_REVERSE_NAT_SK_MAP"
  ],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "map_delete_elem",
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
    "sk_reuseport",
    "cgroup_sysctl",
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
    "static __always_inline int __sock6_xlate_rev (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "    struct ipv6_revnat_tuple key = {}\n",
    "    ;\n",
    "    struct ipv6_revnat_entry *val;\n",
    "    key.cookie = sock_local_cookie (ctx);\n",
    "    key.port = ctx_dst_port (ctx);\n",
    "    ctx_get_v6_address (ctx, &key.address);\n",
    "    val = map_lookup_elem (& LB6_REVERSE_NAT_SK_MAP, & key);\n",
    "    if (val) {\n",
    "        struct lb6_service *svc;\n",
    "        struct lb6_key svc_key = {\n",
    "            .address = val->address,\n",
    "            .dport = val->port,}\n",
    "        ;\n",
    "        svc = lb6_lookup_service (& svc_key, true);\n",
    "        if (!svc)\n",
    "            svc = sock6_wildcard_lookup_full (&svc_key, ctx_in_hostns (ctx, NULL));\n",
    "        if (!svc || svc->rev_nat_index != val->rev_nat_index) {\n",
    "            map_delete_elem (&LB6_REVERSE_NAT_SK_MAP, &key);\n",
    "            update_metrics (0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);\n",
    "            return -ENOENT;\n",
    "        }\n",
    "        ctx_set_v6_address (ctx, &val->address);\n",
    "        ctx_set_port (ctx, val->port);\n",
    "        return 0;\n",
    "    }\n",
    "\n",
    "#endif /* ENABLE_IPV6 */\n",
    "    return sock6_xlate_rev_v4_in_v6 (ctx);\n",
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
static __always_inline int __sock6_xlate_rev(struct bpf_sock_addr *ctx)
{
#ifdef ENABLE_IPV6
	struct ipv6_revnat_tuple key = {};
	struct ipv6_revnat_entry *val;

	key.cookie = sock_local_cookie(ctx);
	key.port = ctx_dst_port(ctx);
	ctx_get_v6_address(ctx, &key.address);

	val = map_lookup_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
	if (val) {
		struct lb6_service *svc;
		struct lb6_key svc_key = {
			.address	= val->address,
			.dport		= val->port,
		};

		svc = lb6_lookup_service(&svc_key, true);
		if (!svc)
			svc = sock6_wildcard_lookup_full(&svc_key,
						ctx_in_hostns(ctx, NULL));
		if (!svc || svc->rev_nat_index != val->rev_nat_index) {
			map_delete_elem(&LB6_REVERSE_NAT_SK_MAP, &key);
			update_metrics(0, METRIC_INGRESS, REASON_LB_REVNAT_STALE);
			return -ENOENT;
		}

		ctx_set_v6_address(ctx, &val->address);
		ctx_set_port(ctx, val->port);
		return 0;
	}
#endif /* ENABLE_IPV6 */

	return sock6_xlate_rev_v4_in_v6(ctx);
}

__section("cgroup/sendmsg6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1170,
  "endLine": 1174,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_sendmsg",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock6_sendmsg (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock6_xlate_fwd (ctx, true);\n",
    "    return SYS_PROCEED;\n",
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
int sock6_sendmsg(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_fwd(ctx, true);
	return SYS_PROCEED;
}

__section("cgroup/recvmsg6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1177,
  "endLine": 1181,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_recvmsg",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock6_recvmsg (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock6_xlate_rev (ctx);\n",
    "    return SYS_PROCEED;\n",
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
int sock6_recvmsg(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}

__section("cgroup/getpeername6")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1184,
  "endLine": 1188,
  "File": "/home/sayandes/opened_extraction/examples/cilium/bpf_sock.c",
  "funcName": "sock6_getpeername",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
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
    "int sock6_getpeername (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock6_xlate_rev (ctx);\n",
    "    return SYS_PROCEED;\n",
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
int sock6_getpeername(struct bpf_sock_addr *ctx)
{
	__sock6_xlate_rev(ctx);
	return SYS_PROCEED;
}
#endif /* ENABLE_SOCKET_LB_UDP || ENABLE_SOCKET_LB_PEER */
#endif /* ENABLE_IPV6 || ENABLE_IPV4 */

BPF_LICENSE("Dual BSD/GPL");
