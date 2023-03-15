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
  "startLine": 59,
  "endLine": 69,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "lb4_lookup_service",
  "developer_inline_comments": [],
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
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline struct lb4_service *lb4_lookup_service (struct V4_key *key)\n",
    "{\n",
    "    struct lb4_service *svc;\n",
    "    svc = bpf_map_lookup_elem (& v4_svc_map, key);\n",
    "    if (svc) {\n",
    "        return svc;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock_addr *ctx"
  ],
  "output": "static__always_inline__be16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline __be16 ctx_dst_port (const struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    volatile __u32 dport = ctx->user_port;\n",
    "    return (__be16) dport;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
          "Project": "bcc",
          "FunctionName": "bpf_get_prandom_u32",
          "Return Type": "u32",
          "Description": "u32 bpf_get_prandom_u32 Returns a pseudo-random u32. Example in situ: \"https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Atools&type=Code search /tools ",
          "Return": "Returns a pseudo-random u32",
          "Input Prameters": [],
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
    }
  ],
  "helperCallParams": {},
  "startLine": 78,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "sock_select_slot",
  "developer_inline_comments": [],
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
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline __u64 sock_select_slot (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    return ctx->protocol == IPPROTO_TCP ? bpf_get_prandom_u32 () : 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
  "startLine": 82,
  "endLine": 85,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "__lb4_lookup_backend",
  "developer_inline_comments": [],
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
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline struct lb4_backend *__lb4_lookup_backend (__u32 backend_id)\n",
    "{\n",
    "    return bpf_map_lookup_elem (&v4_backend_map, &backend_id);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
  "startLine": 87,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "__lb4_lookup_backend_slot",
  "developer_inline_comments": [],
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
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline struct lb4_service *__lb4_lookup_backend_slot (struct V4_key *key)\n",
    "{\n",
    "    return bpf_map_lookup_elem (&v4_svc_map, key);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
          "Description": "Look for UDP socket matching <[ tuple ]>(IP: 1) , optionally in a child network namespace netns. The return value must be checked , and if non-NULL , released via sk_release(). The <[ ctx ]>(IP: 0) should point to the context of the program , such as the skb or socket (depending on the hook in use). This is used to determine the base network namespace for the lookup. <[ tuple_size ]>(IP: 2) must be one of: sizeof(tuple->ipv4) Look for an IPv4 socket. sizeof(tuple->ipv6) Look for an IPv6 socket. If the <[ netns ]>(IP: 3) is a negative signed 32-bit integer , then the socket lookup table in the <[ netns ]>(IP: 3) associated with the <[ ctx ]>(IP: 0) will will be used. For the TC hooks , this is the <[ netns ]>(IP: 3) of the device in the skb. For socket hooks , this is the <[ netns ]>(IP: 3) of the socket. If <[ netns ]>(IP: 3) is any other signed 32-bit value greater than or equal to zero then it specifies the ID of the <[ netns ]>(IP: 3) relative to the <[ netns ]>(IP: 3) associated with the ctx. <[ netns ]>(IP: 3) values beyond the range of 32-bit integers are reserved for future use. All values for <[ flags ]>(IP: 4) are reserved for future usage , and must be left at zero. This helper is available only if the kernel was compiled with CONFIG_NET configuration option. ",
          "Return": " Pointer  to  struct  sock, or NULL in case of failure.  For sockets with                     reuseport option, the struct  sock result is  from  reuse->socks[]  using                     the hash of the tuple.",
          "Function Name": "sk_lookup_udp",
          "Input Params": [
            "{Type: void ,Var: *ctx}",
            "{Type:  struct sock_tuple ,Var: *tuple}",
            "{Type:  u32 ,Var: tuple_size}",
            "{Type:  u64 ,Var: netns}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "sk_skb",
            "cgroup_sock_addr"
          ],
          "capabilities": [
            "read_sys_info"
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
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "sk_skb",
            "cgroup_sock_addr"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 111,
  "endLine": 136,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "sock4_skip_xlate_if_same_netns",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " const struct lb4_backend *backend"
  ],
  "output": "static__always_inlinebool",
  "helper": [
    "sk_release",
    "sk_lookup_udp",
    "sk_lookup_tcp"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "xdp"
  ],
  "source": [
    "static __always_inline bool sock4_skip_xlate_if_same_netns (struct bpf_sock_addr *ctx, const struct lb4_backend *backend)\n",
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
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx",
    " __be16 dport"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline void ctx_set_port (struct bpf_sock_addr *ctx, __be16 dport)\n",
    "{\n",
    "    ctx->user_port = (__u32) dport;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
  "helperCallParams": {},
  "startLine": 143,
  "endLine": 191,
  "File": "/home/sayandes/opened_extraction/examples/kpng-master/backends/ebpf/bpf/cgroup_connect4.c",
  "funcName": "__sock4_fwd",
  "developer_inline_comments": [],
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
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "static __always_inline int __sock4_fwd (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    struct V4_key key = {\n",
    "        .address = ctx->user_ip4,\n",
    "        .dport = ctx_dst_port (ctx),\n",
    "        .backend_slot = 0,}\n",
    "    ;\n",
    "    struct lb4_service *svc;\n",
    "    struct lb4_service *backend_slot;\n",
    "    struct lb4_backend *backend = NULL;\n",
    "    __u32 backend_id = 0;\n",
    "    svc = lb4_lookup_service (& key);\n",
    "    if (!svc) {\n",
    "        return -ENXIO;\n",
    "    }\n",
    "    const char debug_str [] = \"Entering the kpng ebpf backend, caught a\\\n",
    "  packet destined for my VIP, the address is: %x port is: %x and selected backend id is: %x\\n\";\n",
    "    bpf_trace_printk (debug_str, sizeof (debug_str), key.address, key.dport, svc->backend_id);\n",
    "    if (backend_id == 0) {\n",
    "        key.backend_slot = (sock_select_slot (ctx) % svc->count) + 1;\n",
    "        backend_slot = __lb4_lookup_backend_slot (& key);\n",
    "        if (!backend_slot) {\n",
    "            return -ENOENT;\n",
    "        }\n",
    "        backend_id = backend_slot->backend_id;\n",
    "        backend = __lb4_lookup_backend (backend_id);\n",
    "    }\n",
    "    if (!backend) {\n",
    "        return -ENOENT;\n",
    "    }\n",
    "    if (sock4_skip_xlate_if_same_netns (ctx, backend)) {\n",
    "        return -ENXIO;\n",
    "    }\n",
    "    ctx->user_ip4 = backend->address;\n",
    "    ctx_set_port (ctx, backend->port);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "ctx_set_port",
    "sock4_skip_xlate_if_same_netns",
    "__lb4_lookup_backend_slot",
    "lb4_lookup_service",
    "__lb4_lookup_backend",
    "ctx_dst_port",
    "sock_select_slot"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
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
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_addr *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock",
    "sock_ops",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "raw_tracepoint_writable",
    "perf_event",
    "kprobe",
    "sched_act",
    "sk_skb",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "xdp",
    "lwt_out"
  ],
  "source": [
    "int sock4_connect (struct bpf_sock_addr *ctx)\n",
    "{\n",
    "    __sock4_fwd (ctx);\n",
    "    return SYS_PROCEED;\n",
    "}\n"
  ],
  "called_function_list": [
    "__sock4_fwd"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
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
