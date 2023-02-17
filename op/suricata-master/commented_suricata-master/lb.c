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

#define LINUX_VERSION_CODE 263682

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    fmt",
          " sizeoffmt",
          " src",
          " dst",
          " nhoff"
        ]
      }
    ]
  },
  "startLine": 41,
  "endLine": 57,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/lb.c",
  "funcName": "ipv4_hash",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__always_inlineint",
  "helper": [
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
static __always_inline int ipv4_hash(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 src, dst;

    nhoff = skb->cb[0];
    src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

#if 0
    char fmt[] = "Got addr: %x -> %x at %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), src, dst, nhoff);
    //char fmt2[] = "Got hash %u\n";
    //bpf_trace_printk(fmt2, sizeof(fmt2), src + dst);
#endif
    return  src + dst;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 59,
  "endLine": 67,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/lb.c",
  "funcName": "ipv6_addr_hash",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u64 off"
  ],
  "output": "staticinline__u32",
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
static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
    __u64 w0 = load_word(ctx, off);
    __u64 w1 = load_word(ctx, off + 4);
    __u64 w2 = load_word(ctx, off + 8);
    __u64 w3 = load_word(ctx, off + 12);

    return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 81,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/lb.c",
  "funcName": "ipv6_hash",
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
static __always_inline int ipv6_hash(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 src_hash, dst_hash;

    nhoff = skb->cb[0];
    src_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, saddr));
    dst_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, daddr));

    return src_hash + dst_hash;
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
          " fmt",
          " sizeoffmt"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "                            fmt",
          " sizeoffmt",
          " proto"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "                fmt",
          " sizeoffmt",
          " proto"
        ]
      }
    ]
  },
  "startLine": 83,
  "endLine": 145,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/lb.c",
  "funcName": "lb",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\loadbalancer\\)",
  "helper": [
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
int  __section("loadbalancer") lb(struct __sk_buff *skb) {
    __u64 nhoff = ETH_HLEN;
    __u16 proto = load_half(skb, ETH_HLEN - ETH_TLEN);
    __u16 ret = proto;
    switch (proto) {
        case ETH_P_8021Q:
        case ETH_P_8021AD:
            {
                __u16 vproto = load_half(skb, nhoff +  offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
                switch(vproto) {
                    case ETH_P_8021AD:
                    case ETH_P_8021Q:
                        nhoff += sizeof(struct vlan_hdr);
                        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
                        break;
                    default:
                        proto = vproto;
                }

                nhoff += sizeof(struct vlan_hdr);
                skb->cb[0] = nhoff;
                switch (proto) {
                    case ETH_P_IP:
#if 0
                        { char fmt[] = "ipv4\n"; bpf_trace_printk(fmt, sizeof(fmt));}
#endif
                        ret = ipv4_hash(skb);
                        break;
                    case ETH_P_IPV6:
                        ret = ipv6_hash(skb);
                        break;
                    default:
#if 0
                        {
                            char fmt[] = "Dflt VLAN proto %u\n";
                            bpf_trace_printk(fmt, sizeof(fmt), proto);
                            break;
                        }
#else
                        break;
#endif
                }
            }
            break;
        case ETH_P_IP:
            ret = ipv4_hash(skb);
            break;
        case ETH_P_IPV6:
            ret = ipv6_hash(skb);
            break;
        default:
#if 0
            {
                char fmt[] = "Got proto %x\n";
                bpf_trace_printk(fmt, sizeof(fmt), proto);
                break;
            }
#else
            break;
#endif
    }
    return ret;
}

char __license[] __section("license") = "GPL";

/* libbpf needs version section to check sync of eBPF code and kernel
 * but socket filter don't need it */
__u32 __version __section("version") = LINUX_VERSION_CODE;
