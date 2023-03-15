#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/swab.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#ifndef __section
#define __section(NAME) \
    __attribute__((section(NAME), used))
#endif

#ifndef __inline
#define __inline \
    inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
#define lock_xadd(ptr, val) \
    ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) \
    (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define bpf_memcpy __builtin_memcpy

#define MAXELEM 2000

typedef struct cnt_pkt {
    uint32_t drop;
    uint32_t pass;
} pkt_count;

typedef struct iface_desc {
  __u8 mac[ETH_ALEN];
  __u32 ip;
} iface_desc;

#define IP_LEN 4

struct bpf_elf_map iface_map __section("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = ETH_ALEN,
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAXELEM,
};

struct bpf_elf_map iface_ip_map __section("maps") = {
	.type           = BPF_MAP_TYPE_HASH,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(__be32),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem       = MAXELEM,
};

struct bpf_elf_map iface_stat_map __section("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(pkt_count),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAXELEM,
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 76,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/bpf-filter-master/ebpf/drop.c",
  "funcName": "compare_mac",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 *mac1",
    " __u8 *mac2"
  ],
  "output": "static__inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "xdp",
    "lwt_seg6local",
    "kprobe",
    "lwt_out",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "lwt_in",
    "sk_msg",
    "tracepoint",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "cgroup_skb",
    "cgroup_sock",
    "flow_dissector",
    "sock_ops",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __inline int compare_mac (__u8 *mac1, __u8 *mac2)\n",
    "{\n",
    "    if (mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] && mac1[3] == mac2[3] && mac1[4] == mac2[4] && mac1[5] == mac2[5]) {\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
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
static __inline int compare_mac(__u8 *mac1, __u8 *mac2) {
    if (mac1[0] == mac2[0] &&
        mac1[1] == mac2[1] &&
        mac1[2] == mac2[2] &&
        mac1[3] == mac2[3] &&
        mac1[4] == mac2[4] &&
        mac1[5] == mac2[5]) {
        return 1;
    }
    return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 88,
  "endLine": 98,
  "File": "/home/sayandes/opened_extraction/examples/bpf-filter-master/ebpf/drop.c",
  "funcName": "is_broadcast_mac",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 *m"
  ],
  "output": "static__inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "xdp",
    "lwt_seg6local",
    "kprobe",
    "lwt_out",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "lwt_in",
    "sk_msg",
    "tracepoint",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "cgroup_skb",
    "cgroup_sock",
    "flow_dissector",
    "sock_ops",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __inline int is_broadcast_mac (__u8 *m)\n",
    "{\n",
    "    if (m[0] == (__u8) '0xff' && m[1] == (__u8) '0xff' && m[2] == (__u8) '0xff' && m[3] == (__u8) '0xff' && m[4] == (__u8) '0xff' && m[5] == (__u8) '0xff') {\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
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
static __inline int is_broadcast_mac(__u8 *m) {
    if (m[0] == (__u8)'0xff' &&
        m[1] == (__u8)'0xff' &&
        m[2] == (__u8)'0xff' &&
        m[3] == (__u8)'0xff' &&
        m[4] == (__u8)'0xff' &&
        m[5] == (__u8)'0xff') {
        return 1;
    }
    return 0;
}

#define ADD_DROP_STAT(idx, inf) do{ \
    if (idx < MAXELEM) {            \
        lock_xadd(&(inf->drop), 1); \
    }                               \
} while(0);

#define ADD_PASS_STAT(idx, inf) do{ \
    if (idx < MAXELEM) {            \
        lock_xadd(&(inf->pass), 1); \
    }                               \
} while(0);

/*
    This filter attaches on veth (interface in root namespace) and not
    vpeer (interface in the pod namespace) so INGRESS means data coming from pod
    EGRESS means data going towards the pod.
*/
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
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
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
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 117,
  "endLine": 227,
  "File": "/home/sayandes/opened_extraction/examples/bpf-filter-master/ebpf/drop.c",
  "funcName": "filter",
  "developer_inline_comments": [
    {
      "start_line": 13,
      "end_line": 17,
      "text": "/*\n    This filter attaches on veth (interface in root namespace) and not\n    vpeer (interface in the pod namespace) so INGRESS means data coming from pod\n    EGRESS means data going towards the pod.\n*/"
    },
    {
      "start_line": 49,
      "end_line": 49,
      "text": "/* ETH_P_IP in Little Endian Format */"
    },
    {
      "start_line": 61,
      "end_line": 61,
      "text": "// haven't found the stat-entry, unexpected behavior, let packet go through."
    },
    {
      "start_line": 66,
      "end_line": 66,
      "text": "// Mac address lookup"
    },
    {
      "start_line": 69,
      "end_line": 69,
      "text": "/* Unable to get iface MAC. Let the packet through */"
    },
    {
      "start_line": 75,
      "end_line": 75,
      "text": "// IP addresss lookup"
    },
    {
      "start_line": 78,
      "end_line": 78,
      "text": "/* Unable to get iface IP. Let the packet through */"
    },
    {
      "start_line": 84,
      "end_line": 84,
      "text": "// check broadcast messages"
    },
    {
      "start_line": 85,
      "end_line": 85,
      "text": "// Broadcast address should be allowed"
    },
    {
      "start_line": 92,
      "end_line": 92,
      "text": "/* check is packet is coming from pod or going towards pod. */"
    },
    {
      "start_line": 94,
      "end_line": 94,
      "text": "// Packet is going towards the pod. Let is pass"
    },
    {
      "start_line": 98,
      "end_line": 98,
      "text": "// Packet has come from the pod. Check the mac address."
    },
    {
      "start_line": 114,
      "end_line": 114,
      "text": "// MAC Address matches. Now check IP address"
    },
    {
      "start_line": 117,
      "end_line": 117,
      "text": "// If IP addresss do not match"
    },
    {
      "start_line": 124,
      "end_line": 124,
      "text": "// IP address matches"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  iface_stat_map",
    "  iface_map",
    "  iface_ip_map"
  ],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__inlineint",
  "helper": [
    "bpf_map_lookup_elem",
    "TC_ACT_OK",
    "bpf_trace_printk",
    "TC_ACT_SHOT"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __inline int filter (struct  __sk_buff *skb)\n",
    "{\n",
    "    char pkt_fmt [] = \"MAC_FILTER: pkt skb contain mac: %x%x\\n\";\n",
    "    char src_fmt [] = \"MAC_FILTER: expected source mac: %x%x\\n\";\n",
    "    char broadcast [] = \"MAC_FILTER: BROADCAST MESSAGE DETECTED\\n\";\n",
    "    char mac_matched [] = \"MAC_FILTER: MAC MATCHED\\n\";\n",
    "    char mac_unmatched [] = \"MAC_FILTER: MAC DID NOT MATCH\\n\";\n",
    "    char map_error [] = \"MAC_FILTER: Unable to get iface %s from map\\n\";\n",
    "    char ip_matched [] = \"IP_FILTER: IP iface:%x == pkt:%x MATCHED\\n\";\n",
    "    char ip_unmatched [] = \"IP_FILTER: IP iface:%x != pkt:%x DID NOT MATCH\\n\";\n",
    "    char ipstr [] = \"ip\";\n",
    "    char macstr [] = \"mac\";\n",
    "    char statsstr [] = \"stats\";\n",
    "    uint32_t *bytes;\n",
    "    pkt_count *inf;\n",
    "    void *data = (void *) (long) skb->data;\n",
    "    void *data_end = (void *) (long) skb->data_end;\n",
    "    struct ethhdr *eth = data;\n",
    "    uint32_t idx = skb->ifindex;\n",
    "    struct iphdr *ip;\n",
    "    __u8 iface_mac [ETH_ALEN];\n",
    "    __be32 iface_ip;\n",
    "    __u64 l3_offset = sizeof (struct ethhdr);\n",
    "    if (data_end < (void *) eth + l3_offset)\n",
    "        return TC_ACT_SHOT;\n",
    "    if (eth->h_proto != 0x0008) {\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    ip = data + l3_offset;\n",
    "    if ((void *) (ip + 1) > data_end) {\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    inf = bpf_map_lookup_elem (& iface_stat_map, & (idx));\n",
    "    if (!inf) {\n",
    "        bpf_trace_printk (map_error, sizeof (map_error), statsstr);\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    bytes = bpf_map_lookup_elem (& iface_map, & (idx));\n",
    "    if (bytes == NULL) {\n",
    "        bpf_trace_printk (map_error, sizeof (map_error), macstr);\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    bpf_memcpy (iface_mac, bytes, ETH_ALEN);\n",
    "    bytes = bpf_map_lookup_elem (& iface_ip_map, & (idx));\n",
    "    if (bytes == NULL) {\n",
    "        bpf_trace_printk (map_error, sizeof (map_error), ipstr);\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    bpf_memcpy (&iface_ip, bytes, sizeof (__be32));\n",
    "    if ((is_broadcast_mac (eth->h_source) == 1) || (is_broadcast_mac (eth->h_dest) == 1)) {\n",
    "        bpf_trace_printk (broadcast, sizeof (broadcast));\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    if (compare_mac (eth->h_dest, iface_mac) == 1) {\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    __u8 *pkt_mac = (__u8 *) eth->h_source;\n",
    "    __be32 pkt_ip = ip->saddr;\n",
    "    if (compare_mac (pkt_mac, iface_mac) == 0) {\n",
    "        bpf_trace_printk (mac_unmatched, sizeof (mac_unmatched));\n",
    "        bpf_trace_printk (src_fmt, sizeof (src_fmt), (iface_mac[0] << 16 | iface_mac[1] << 8 | iface_mac[2]), (iface_mac[3] << 16 | iface_mac[4] << 8 | iface_mac[5]));\n",
    "        bpf_trace_printk (pkt_fmt, sizeof (pkt_fmt), (pkt_mac[0] << 16 | pkt_mac[1] << 8 | pkt_mac[2]), (pkt_mac[3] << 16 | pkt_mac[4] << 8 | pkt_mac[5]));\n",
    "        ADD_DROP_STAT (idx, inf);\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    bpf_trace_printk (mac_matched, sizeof (mac_matched));\n",
    "    if (iface_ip != pkt_ip) {\n",
    "        bpf_trace_printk (ip_unmatched, sizeof (ip_unmatched), iface_ip, pkt_ip);\n",
    "        ADD_DROP_STAT (idx, inf);\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    bpf_trace_printk (ip_matched, sizeof (ip_matched), iface_ip, pkt_ip);\n",
    "    ADD_PASS_STAT (idx, inf);\n",
    "    return TC_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "ADD_DROP_STAT",
    "bpf_memcpy",
    "is_broadcast_mac",
    "ADD_PASS_STAT",
    "compare_mac"
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
static __inline int filter(struct __sk_buff *skb)
{
    char pkt_fmt[]       = "MAC_FILTER: pkt skb contain mac: %x%x\n";
    char src_fmt[]       = "MAC_FILTER: expected source mac: %x%x\n";
    char broadcast[]     = "MAC_FILTER: BROADCAST MESSAGE DETECTED\n";
    char mac_matched[]   = "MAC_FILTER: MAC MATCHED\n";
    char mac_unmatched[] = "MAC_FILTER: MAC DID NOT MATCH\n";
    char map_error[]     = "MAC_FILTER: Unable to get iface %s from map\n";
    char ip_matched[]    = "IP_FILTER: IP iface:%x == pkt:%x MATCHED\n";
    char ip_unmatched[]  = "IP_FILTER: IP iface:%x != pkt:%x DID NOT MATCH\n";
    char ipstr[]         = "ip";
    char macstr[]        = "mac";
    char statsstr[]      = "stats";

    uint32_t *bytes;
    pkt_count *inf;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    uint32_t idx = skb->ifindex;
    struct iphdr *ip;

    __u8 iface_mac[ETH_ALEN];
    __be32 iface_ip;

    __u64 l3_offset = sizeof(struct ethhdr);

    if (data_end < (void *)eth + l3_offset)
        return TC_ACT_SHOT;

    /* ETH_P_IP in Little Endian Format */
    if (eth->h_proto != 0x0008) {
        return TC_ACT_OK;
    }

    ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    inf = bpf_map_lookup_elem(&iface_stat_map, &(idx));
    if (!inf) {
        // haven't found the stat-entry, unexpected behavior, let packet go through.
        bpf_trace_printk(map_error, sizeof(map_error), statsstr);
        return TC_ACT_OK;
    }

    // Mac address lookup
    bytes = bpf_map_lookup_elem(&iface_map, &(idx));
    if (bytes == NULL) {
        /* Unable to get iface MAC. Let the packet through */
        bpf_trace_printk(map_error, sizeof(map_error), macstr);
        return TC_ACT_OK;
    }
    bpf_memcpy(iface_mac, bytes, ETH_ALEN);

    // IP addresss lookup
    bytes = bpf_map_lookup_elem(&iface_ip_map, &(idx));
    if (bytes == NULL) {
        /* Unable to get iface IP. Let the packet through */
        bpf_trace_printk(map_error, sizeof(map_error), ipstr);
        return TC_ACT_OK;
    }
    bpf_memcpy(&iface_ip, bytes, sizeof(__be32));

    // check broadcast messages
    // Broadcast address should be allowed
    if ((is_broadcast_mac(eth->h_source) == 1) ||
        (is_broadcast_mac(eth->h_dest) == 1)) {
        bpf_trace_printk(broadcast, sizeof(broadcast));
        return TC_ACT_OK;
    }

    /* check is packet is coming from pod or going towards pod. */
    if (compare_mac(eth->h_dest, iface_mac) == 1) {
        // Packet is going towards the pod. Let is pass
        return TC_ACT_OK;
    }

    // Packet has come from the pod. Check the mac address.
    __u8 *pkt_mac = (__u8 *)eth->h_source;
    __be32 pkt_ip = ip->saddr;

    if (compare_mac(pkt_mac, iface_mac) == 0) {
        bpf_trace_printk(mac_unmatched, sizeof(mac_unmatched));
        bpf_trace_printk(src_fmt, sizeof(src_fmt),
                         (iface_mac[0] << 16 | iface_mac[1] << 8 | iface_mac[2]),
                         (iface_mac[3] << 16 | iface_mac[4] << 8 | iface_mac[5]));
        bpf_trace_printk(pkt_fmt, sizeof(pkt_fmt),
                         (pkt_mac[0] << 16 | pkt_mac[1] << 8 | pkt_mac[2]),
                         (pkt_mac[3] << 16 | pkt_mac[4] << 8 | pkt_mac[5]));
        ADD_DROP_STAT(idx, inf);
        return TC_ACT_SHOT;
    }

    // MAC Address matches. Now check IP address
    bpf_trace_printk(mac_matched, sizeof(mac_matched));

    // If IP addresss do not match
    if (iface_ip != pkt_ip) {
        bpf_trace_printk(ip_unmatched, sizeof(ip_unmatched), iface_ip, pkt_ip);
        ADD_DROP_STAT(idx, inf);
        return TC_ACT_SHOT;
    }

    // IP address matches
    bpf_trace_printk(ip_matched, sizeof(ip_matched), iface_ip, pkt_ip);
    ADD_PASS_STAT(idx, inf);
    return TC_ACT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 229,
  "endLine": 232,
  "File": "/home/sayandes/opened_extraction/examples/bpf-filter-master/ebpf/drop.c",
  "funcName": "bpf_filter",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "xdp",
    "lwt_seg6local",
    "kprobe",
    "lwt_out",
    "raw_tracepoint_writable",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "cgroup_device",
    "perf_event",
    "lwt_in",
    "sk_msg",
    "tracepoint",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "cgroup_skb",
    "cgroup_sock",
    "flow_dissector",
    "sock_ops",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "int bpf_filter (struct  __sk_buff *skb)\n",
    "{\n",
    "    return filter (skb);\n",
    "}\n"
  ],
  "called_function_list": [
    "filter"
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
__section("classifier_bpf_filter") int bpf_filter(struct __sk_buff *skb)
{
    return filter(skb);
}
