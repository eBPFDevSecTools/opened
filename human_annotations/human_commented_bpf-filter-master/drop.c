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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 *mac1",
    " __u8 *mac2"
  ],
  "output": "static__inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint_writable",
    "sk_msg",
    "sched_act",
    "cgroup_sysctl",
    "raw_tracepoint",
    "lwt_xmit",
    "lwt_out",
    "cgroup_device",
    "socket_filter",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "sk_skb",
    "sched_cls",
    "cgroup_sock",
    "sock_ops",
    "lwt_in",
    "tracepoint",
    "perf_event",
    "sk_reuseport",
    "kprobe",
    "flow_dissector",
    "cgroup_skb"
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
  "humanFuncDescription": [
    {
      "description": "This function compares mac addresses represented by two unsigned char arrays of length 6 mac1 and mac2 passed as arguments, returns 1 if true else 0",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-22"
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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 *m"
  ],
  "output": "static__inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint_writable",
    "sk_msg",
    "sched_act",
    "cgroup_sysctl",
    "raw_tracepoint",
    "lwt_xmit",
    "lwt_out",
    "cgroup_device",
    "socket_filter",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "sk_skb",
    "sched_cls",
    "cgroup_sock",
    "sock_ops",
    "lwt_in",
    "tracepoint",
    "perf_event",
    "sk_reuseport",
    "kprobe",
    "flow_dissector",
    "cgroup_skb"
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
  "humanFuncDescription": [
    {
      "description": "This function returns if the mac addressed m passed as an unsigned char array of length 6 equals 0xffffffffffff which is the broadcast mac, returns 1 if equal else 0",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "        inf ",
        "inpVar": [
          " &iface_stat_map",
          " &idx"
        ]
      },
      {
        "opVar": "            bytes ",
        "inpVar": [
          " &iface_map",
          " &idx"
        ]
      },
      {
        "opVar": "        bytes ",
        "inpVar": [
          " &iface_ip_map",
          " &idx"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "                map_error",
          " sizeofmap_error",
          " statsstr"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "                map_error",
          " sizeofmap_error",
          " macstr"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "                map_error",
          " sizeofmap_error",
          " ipstr"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        broadcast",
          " sizeofbroadcast"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        mac_unmatched",
          " sizeofmac_unmatched"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        src_fmt",
          " sizeofsrc_fmt",
          "                         iface_mac[0] << 16 | iface_mac[1] << 8 | iface_mac[2]",
          "                         iface_mac[3] << 16 | iface_mac[4] << 8 | iface_mac[5]"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        pkt_fmt",
          " sizeofpkt_fmt",
          "                         pkt_mac[0] << 16 | pkt_mac[1] << 8 | pkt_mac[2]",
          "                         pkt_mac[3] << 16 | pkt_mac[4] << 8 | pkt_mac[5]"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "            mac_matched",
          " sizeofmac_matched"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        ip_unmatched",
          " sizeofip_unmatched",
          " iface_ip",
          " pkt_ip"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "            ip_matched",
          " sizeofip_matched",
          " iface_ip",
          " pkt_ip"
        ]
      }
    ]
  },
  "startLine": 117,
  "endLine": 227,
  "File": "/home/sayandes/opened_extraction/examples/bpf-filter-master/ebpf/drop.c",
  "funcName": "filter",
  "updateMaps": [],
  "readMaps": [
    "  iface_map",
    "  iface_ip_map",
    "  iface_stat_map"
  ],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__inlineint",
  "helper": [
    "bpf_trace_printk",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint_writable",
    "sk_msg",
    "sched_act",
    "cgroup_sysctl",
    "raw_tracepoint",
    "lwt_xmit",
    "lwt_out",
    "cgroup_device",
    "socket_filter",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "sk_skb",
    "sched_cls",
    "cgroup_sock",
    "sock_ops",
    "lwt_in",
    "tracepoint",
    "perf_event",
    "sk_reuseport",
    "kprobe",
    "flow_dissector",
    "cgroup_skb"
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
  "humanFuncDescription": [
    {
      "description": "This function performs the action of a filter which allows packets only with certain mac and ip address to pass through.The filter described below is to be attached on the root interface of a pod's veth pair at TC layer and filters the outgoing traffic from pod. It takes in a packet in sk_buff form as argument. It first checks if the packet is well formed. If it is, it will reads a map called iface_stat_map using the packet ingress interface as the key, this map stores the counter of passed or dropped packets. Then, the filter reads maps called iface_map and iface_ip_map also with ingress interface of the packet as the key. First map returns the mac address which is allowed to pass through the interface and second contains the ip address which is allowed.  The filter applied is of this form, allow packets coming from the pod only in these cases, 1) if the source or dest mac are broadcast addresses then allow,  2) if the packet source mac address matches that of the pod then allow, 3) if the packet source ip matches that of the pod then allow.Filter doesn't stop the traffic going towards the pod.Note that all the above filters are applied to the packet and traffic is allowed only in the cases mentioned aboveIt also prints the matching/unmatching mac or ip addresses.Returns TC_ACT_OK if filter passes else TC_ACT_SHOT. The filter also records the PASS or SHOT statistics in the map iface_stat_map",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint_writable",
    "sk_msg",
    "sched_act",
    "cgroup_sysctl",
    "raw_tracepoint",
    "lwt_xmit",
    "lwt_out",
    "cgroup_device",
    "socket_filter",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "sk_skb",
    "sched_cls",
    "cgroup_sock",
    "sock_ops",
    "lwt_in",
    "tracepoint",
    "perf_event",
    "sk_reuseport",
    "kprobe",
    "flow_dissector",
    "cgroup_skb"
  ],
  "source": [
    "int bpf_filter (struct  __sk_buff *skb)\n",
    "{\n",
    "    return filter (skb);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "This is a wrapper function which calls the base function filter with the same arument passed to it and returns its value",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
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
__section("classifier_bpf_filter") int bpf_filter(struct __sk_buff *skb)
{
    return filter(skb);
}
