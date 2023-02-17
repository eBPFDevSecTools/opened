/*
    Flows v2. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <stdbool.h>
#include <linux/if_ether.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "flow.h"

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
// The userspace will aggregate them into a single flow.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
} aggregated_flows SEC(".maps");

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;
volatile const u8 trace_messages = 0;

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// sets the TCP header flags for connection information
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 79,
  "endLine": 104,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "set_flags",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct tcphdr *th",
    " u16 *flags"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
static inline void set_flags(struct tcphdr *th, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake. 
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin ) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst ) {
        // If both ACK and RST are set, then it is abrupt connection termination. 
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}
// sets flow fields from IPv4 header information
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 106,
  "endLine": 138,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "fill_iphdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr *ip",
    " void *data_end",
    " flow_id *id",
    " u16 *flags"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    id->transport_protocol = ip->protocol;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
            set_flags(tcp, flags);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 141,
  "endLine": 171,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "fill_ip6hdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ipv6hdr *ip",
    " void *data_end",
    " flow_id *id",
    " u16 *flags"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    id->src_ip = ip->saddr;
    id->dst_ip = ip->daddr;
    id->transport_protocol = ip->nexthdr;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
            set_flags(tcp, flags);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 197,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "fill_ethhdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ethhdr *eth",
    " void *data_end",
    " flow_id *id",
    " u16 *flags"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, id, flags);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, id, flags);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        memset(&(id->src_ip), 0, sizeof(struct in6_addr));
        memset(&(id->dst_ip), 0, sizeof(struct in6_addr));
        id->transport_protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
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
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
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
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Get a pseudo-random number. From a security point of view , this helper uses its own pseudo-random internal state , and cannot be used to infer the seed of other random functions in the kernel. However , it is essential to note that the generator used by the helper is not cryptographically secure. ",
          "Return": " A random 32-bit unsigned value.",
          "Function Name": "bpf_get_prandom_u32",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
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
        "opVar": "        if (sampling !",
        "inpVar": [
          " 0 &&  % sampling !"
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "    u64 current_time ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_map_lookup_elem": [
      {
        "opVar": "            flow_metrics *aggregate_flow ",
        "inpVar": [
          " &aggregated_flows",
          " &id"
        ]
      }
    ],
    "bpf_map_update_elem": [
      {
        "opVar": "        long ret ",
        "inpVar": [
          " &aggregated_flows",
          " &id",
          " aggregate_flow",
          " BPF_ANY"
        ]
      },
      {
        "opVar": "                        long ret ",
        "inpVar": [
          " &aggregated_flows",
          " &id",
          " &new_flow",
          " BPF_ANY"
        ]
      }
    ]
  },
  "startLine": 199,
  "endLine": 276,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "flow_monitor",
  "updateMaps": [
    "  aggregated_flows"
  ],
  "readMaps": [
    " aggregated_flows"
  ],
  "input": [
    "struct  __sk_buff *skb",
    " u8 direction"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "bpf_get_prandom_u32",
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "tracepoint",
    "lwt_in",
    "sched_cls",
    "flow_dissector"
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
static inline int flow_monitor(struct __sk_buff *skb, u8 direction) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_OK;
    }
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    flow_id id;
    u64 current_time = bpf_ktime_get_ns();
    struct ethhdr *eth = data;
    u16 flags = 0;
    if (fill_ethhdr(eth, data_end, &id, &flags) == DISCARD) {
        return TC_ACT_OK;
    }
    id.if_index = skb->ifindex;
    id.direction = direction;

    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ts = current_time;
        // it might happen that start_mono_time hasn't been set due to
        // the way percpu hashmap deal with concurrent map entries
        if (aggregate_flow->start_mono_time_ts == 0) {
            aggregate_flow->start_mono_time_ts = current_time;
        }
        aggregate_flow->flags |= flags;
        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            bpf_printk("error updating flow %d\n", ret);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .start_mono_time_ts = current_time,
            .end_mono_time_ts = current_time,
            .flags = flags, 
        };

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userpace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (!record) {
                if (trace_messages) {
                    bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
                return TC_ACT_OK;
            }
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, 0);
        }
    }
    return TC_ACT_OK;
}
SEC("tc_ingress")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 278,
  "endLine": 280,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "ingress_flow_parse",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
int ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 283,
  "endLine": 285,
  "File": "/home/sayandes/opened_extraction/examples/netobserv-bpf-main/flows.c",
  "funcName": "egress_flow_parse",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "sock_ops",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "sk_msg",
    "cgroup_sock_addr",
    "sk_skb",
    "lwt_seg6local",
    "lwt_xmit",
    "sched_act",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "raw_tracepoint",
    "xdp",
    "socket_filter",
    "lwt_in",
    "tracepoint",
    "sched_cls",
    "flow_dissector"
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
int egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}
char _license[] SEC("license") = "GPL";
