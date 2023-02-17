/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define DEBUG 0

#define LINUX_VERSION_CODE 263682

struct bpf_map_def SEC("maps") ipv4_drop = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32768,
};

struct vlan_hdr {
    __u16   h_vlan_TCI;
    __u16   h_vlan_encapsulated_proto;
};

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
        "opVar": "    value ",
        "inpVar": [
          " &ipv4_drop",
          " &ip"
        ]
      },
      {
        "opVar": "    value ",
        "inpVar": [
          " &ipv4_drop",
          " &ip"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "        fmt",
          " sizeoffmt",
          " value"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "        fmt",
          " sizeoffmt",
          " value"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "    fmt",
          " sizeoffmt"
        ]
      }
    ]
  },
  "startLine": 46,
  "endLine": 81,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/filter.c",
  "funcName": "ipv4_filter",
  "updateMaps": [],
  "readMaps": [
    "  ipv4_drop"
  ],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "lwt_xmit",
    "perf_event",
    "socket_filter",
    "flow_dissector",
    "sched_act",
    "lwt_out",
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "sk_skb",
    "sk_reuseport",
    "sk_msg",
    "lwt_in",
    "sched_cls",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "sock_ops",
    "xdp",
    "raw_tracepoint"
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
static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 *value;
    __u32 ip = 0;

    nhoff = skb->cb[0];

    ip = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for saddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

    ip = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for daddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

#if DEBUG
    char fmt[] = "Nothing so ok\n";
    bpf_trace_printk(fmt, sizeof(fmt));
#endif
    return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/filter.c",
  "funcName": "ipv6_filter",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "lwt_xmit",
    "perf_event",
    "socket_filter",
    "flow_dissector",
    "sched_act",
    "lwt_out",
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "sk_skb",
    "sk_reuseport",
    "sk_msg",
    "lwt_in",
    "sched_cls",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "sock_ops",
    "xdp",
    "raw_tracepoint"
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
static __always_inline int ipv6_filter(struct __sk_buff *skb)
{
    return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 88,
  "endLine": 110,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/filter.c",
  "funcName": "hashfilter",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\filter\\)",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "lwt_xmit",
    "perf_event",
    "socket_filter",
    "flow_dissector",
    "sched_act",
    "lwt_out",
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "sk_skb",
    "sk_reuseport",
    "sk_msg",
    "lwt_in",
    "sched_cls",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "sock_ops",
    "xdp",
    "raw_tracepoint"
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
int SEC("filter") hashfilter(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb);
        case ETH_P_IPV6:
            return ipv6_filter(skb);
        default:
            break;
    }
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
