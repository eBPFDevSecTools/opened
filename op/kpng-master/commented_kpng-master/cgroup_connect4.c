/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#include "uapi/linux/bpf.h"
#include "bpf/bpf_helpers.h"
#include <linux/types.h>
#include <stdbool.h>
#include <errno.h>

#define SYS_REJECT 0
#define SYS_PROCEED 1
#define DEFAULT_MAX_EBPF_MAP_ENTRIES 65536
#define IPPROTO_TCP 6

char __license[] SEC("license") = "Dual BSD/GPL";

struct V4_key {
  __be32 address;     /* Service virtual IPv4 address  4*/
  __be16 dport;       /* L4 port filter, if unset, all ports apply   */
  __u16 backend_slot; /* Backend iterator, 0 indicates the svc frontend  2*/
};

struct lb4_service {
  union {
    __u32 backend_id;       /* Backend ID in lb4_backends */
    __u32 affinity_timeout; /* In seconds, only for svc frontend */
    __u32 l7_lb_proxy_port; /* In host byte order, only when flags2 &&
                               SVC_FLAG_L7LOADBALANCER */
  };
  /* For the service frontend, count denotes number of service backend
   * slots (otherwise zero).
   */
  __u16 count;
  __u16 rev_nat_index; /* Reverse NAT ID in lb4_reverse_nat */
  __u8 flags;
  __u8 flags2;
  __u8 pad[2];
};

struct lb4_backend {
  __be32 address; /* Service endpoint IPv4 address */
  __be16 port;    /* L4 port filter */
  __u8 flags;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH); 
  __type(key, struct V4_key);
  __type(value, struct lb4_service); 
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENTRIES);
} v4_svc_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH); 
  __type(key, __u32);
  __type(value, struct lb4_backend); 
  __uint(max_entries, DEFAULT_MAX_EBPF_MAP_ENTRIES);
} v4_backend_map SEC(".maps");

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "  svc ",
        "inpVar": [
          " &v4_svc_map",
          " key"
        ]
      }
    ]
  },
  "startLine": 59,
  "endLine": 69,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "*lb4_lookup_service",
  "updateMaps": [],
  "readMaps": [
    "  v4_svc_map"
  ],
  "input": [
    "struct V4_key *key"
  ],
  "output": "static__always_inlinestructlb4_service",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
lb4_lookup_service(struct V4_key *key) {
  struct lb4_service *svc;

  svc = bpf_map_lookup_elem(&v4_svc_map, key);
  if (svc) {
    return svc;
  }

  return NULL;
}

/* Hack due to missing narrow ctx access. */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 72,
  "endLine": 76,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "ctx_dst_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__be16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
static __always_inline __be16 ctx_dst_port(const struct bpf_sock_addr *ctx) {
  volatile __u32 dport = ctx->user_port;

  return (__be16)dport;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Get a pseudo-random number. From a security point of view , this helper uses its own pseudo-random internal state , and cannot be used to infer the seed of other random functions in the kernel. However , it is essential to note that the generator used by the helper is not cryptographically secure. ",
          "Return": " A random 32-bit unsigned value.",
          "Function Name": "bpf_get_prandom_u32",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_prandom_u32": [
      {
        "opVar": "  return ctx->protocol ",
        "inpVar": [
          ""
        ]
      }
    ]
  },
  "startLine": 78,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "sock_select_slot",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__u64",
  "helper": [
    "bpf_get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
static __always_inline __u64 sock_select_slot(struct bpf_sock_addr *ctx) {
  return ctx->protocol == IPPROTO_TCP ? bpf_get_prandom_u32() : 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "  return &v4_backend_map",
          " &backend_id"
        ]
      }
    ]
  },
  "startLine": 82,
  "endLine": 85,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "*__lb4_lookup_backend",
  "updateMaps": [],
  "readMaps": [
    " v4_backend_map"
  ],
  "input": [
    "__u32 backend_id"
  ],
  "output": "static__always_inlinestructlb4_backend",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
static __always_inline struct lb4_backend *
__lb4_lookup_backend(__u32 backend_id) {
  return bpf_map_lookup_elem(&v4_backend_map, &backend_id);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "  return &v4_svc_map",
          " key"
        ]
      }
    ]
  },
  "startLine": 87,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "*__lb4_lookup_backend_slot",
  "updateMaps": [],
  "readMaps": [
    " v4_svc_map"
  ],
  "input": [
    "struct V4_key *key"
  ],
  "output": "static__always_inlinestructlb4_service",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
__lb4_lookup_backend_slot(struct V4_key *key) {
  return bpf_map_lookup_elem(&v4_svc_map, key);
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
        },
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
    "sk_lookup_tcp": [
      {
        "opVar": "  case IPPROTO_TCP:    sk ",
        "inpVar": [
          " ctx",
          " &tuple",
          " sizeoftuple.ipv4",
          " BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_lookup_udp": [
      {
        "opVar": "  case IPPROTO_UDP:    sk ",
        "inpVar": [
          " ctx",
          " &tuple",
          " sizeoftuple.ipv4",
          " BPF_F_CURRENT_NETNS",
          " 0"
        ]
      }
    ],
    "sk_release": [
      {
        "opVar": "NA",
        "inpVar": [
          "    sk"
        ]
      }
    ]
  },
  "startLine": 111,
  "endLine": 136,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "sock4_skip_xlate_if_same_netns",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const struct lb4_backend *backend"
  ],
  "output": "static__always_inlinebool",
  "helper": [
    "sk_release",
    "sk_lookup_tcp",
    "sk_lookup_udp"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "cgroup_sock_addr",
    "sk_skb",
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
    {}
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
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx,
                               const struct lb4_backend *backend) {
#ifdef BPF_HAVE_SOCKET_LOOKUP
  struct bpf_sock_tuple tuple = {
      .ipv4.daddr = backend->address,
      .ipv4.dport = backend->port,
  };
  struct bpf_sock *sk = NULL;

  switch (ctx->protocol) {
  case IPPROTO_TCP:
    sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    break;
  case IPPROTO_UDP:
    sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
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
  "helperCallParams": {},
  "startLine": 138,
  "endLine": 141,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "ctx_set_port",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " __be16 dport"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
static __always_inline void ctx_set_port(struct bpf_sock_addr *ctx,
                                         __be16 dport) {
  ctx->user_port = (__u32)dport;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    debug_str",
          " sizeofdebug_str",
          "  key.address",
          " key.dport",
          " svc->backend_id"
        ]
      }
    ]
  },
  "startLine": 143,
  "endLine": 191,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "__sock4_fwd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
static __always_inline int __sock4_fwd(struct bpf_sock_addr *ctx) {
  struct V4_key key = {
      .address = ctx->user_ip4,
      .dport = ctx_dst_port(ctx),
      .backend_slot = 0,
  };

  struct lb4_service *svc;
  struct lb4_service *backend_slot;
  struct lb4_backend *backend = NULL;

  __u32 backend_id = 0;

  svc = lb4_lookup_service(&key);
  if (!svc) {
    return -ENXIO;
  }

  // Logs are in /sys/kernel/debug/tracing/trace_pipe

  const char debug_str[] = "Entering the kpng ebpf backend, caught a\
  packet destined for my VIP, the address is: %x port is: %x and selected backend id is: %x\n";
  
  bpf_trace_printk(debug_str, sizeof(debug_str),  key.address, key.dport, svc->backend_id);

  if (backend_id == 0) {
    key.backend_slot = (sock_select_slot(ctx) % svc->count) + 1;
    backend_slot = __lb4_lookup_backend_slot(&key);
    if (!backend_slot) {
      return -ENOENT;
    }

    backend_id = backend_slot->backend_id;
    backend = __lb4_lookup_backend(backend_id);
  }

  if (!backend) {
    return -ENOENT;
  }

  if (sock4_skip_xlate_if_same_netns(ctx, backend)) {
    return -ENXIO;
  }

  ctx->user_ip4 = backend->address;
  ctx_set_port(ctx, backend->port);

  return 0;
}

SEC("cgroup/connect4")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 194,
  "endLine": 198,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "sock4_connect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "sock_ops",
    "perf_event",
    "lwt_out",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_skb",
    "xdp",
    "sched_act",
    "cgroup_sock_addr",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock",
    "lwt_in",
    "kprobe",
    "cgroup_sysctl",
    "sched_cls",
    "raw_tracepoint_writable",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint",
    "socket_filter",
    "sk_msg"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
int sock4_connect(struct bpf_sock_addr *ctx) {

  __sock4_fwd(ctx);
  return SYS_PROCEED;
}