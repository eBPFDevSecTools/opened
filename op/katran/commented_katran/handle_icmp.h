/* Copyright (C) 2018-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __HANDLE_ICMP_H
#define __HANDLE_ICMP_H

/*
 * This file contains all routines which are responsible for parsing
 * and handling ICMP packets
 */

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>

#include "balancer_consts.h"
#include "balancer_helpers.h"
#include "balancer_structs.h"
#include "bpf.h"
#include "bpf_endian.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_alter_or_redo_processing_or_interface",
      "pkt_alter_or_redo_processing_or_interface": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_TX",
          "Return": 3,
          "Description": "an efficient option to transmit the network packet out of the same NIC it just arrived on again. This is typically useful when few nodes are implementing, for example, firewalling with subsequent load balancing in a cluster and thus act as a hairpinned load balancer pushing the incoming packets back into the switch after rewriting them in XDP BPF.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_alter_or_redo_processing_or_interface"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 38,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "swap_mac_and_send",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_TX"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int swap_mac_and_send (void *data, void *data_end)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    unsigned char tmp_mac [ETH_ALEN];\n",
    "    eth = data;\n",
    "    memcpy (tmp_mac, eth->h_source, ETH_ALEN);\n",
    "    memcpy (eth->h_source, eth->h_dest, ETH_ALEN);\n",
    "    memcpy (eth->h_dest, tmp_mac, ETH_ALEN);\n",
    "    return XDP_TX;\n",
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
__attribute__((__always_inline__)) static inline int swap_mac_and_send(
    void* data,
    void* data_end) {
  struct ethhdr* eth;
  unsigned char tmp_mac[ETH_ALEN];
  eth = data;
  memcpy(tmp_mac, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, tmp_mac, ETH_ALEN);
  return XDP_TX;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 58,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "swap_mac",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " struct ethhdr *orig_eth"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "lwt_seg6local",
    "sk_skb",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "perf_event",
    "cgroup_sysctl",
    "xdp",
    "sched_cls",
    "cgroup_sock_addr",
    "socket_filter",
    "cgroup_skb",
    "kprobe",
    "lwt_out",
    "tracepoint",
    "lwt_in",
    "cgroup_device",
    "sched_act",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "sock_ops",
    "sk_reuseport"
  ],
  "source": [
    "static inline void swap_mac (void *data, struct ethhdr *orig_eth)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    eth = data;\n",
    "    memcpy (eth->h_source, orig_eth->h_dest, ETH_ALEN);\n",
    "    memcpy (eth->h_dest, orig_eth->h_source, ETH_ALEN);\n",
    "    eth->h_proto = orig_eth->h_proto;\n",
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
__attribute__((__always_inline__)) static inline void swap_mac(
    void* data,
    struct ethhdr* orig_eth) {
  struct ethhdr* eth;
  eth = data;
  memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
  eth->h_proto = orig_eth->h_proto;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 60,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp_reply",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int send_icmp_reply (void *data, void *data_end)\n",
    "{\n",
    "    struct iphdr *iph;\n",
    "    struct icmphdr *icmp_hdr;\n",
    "    __u32 tmp_addr = 0;\n",
    "    __u64 csum = 0;\n",
    "    __u64 off = 0;\n",
    "    if ((data + sizeof (struct ethhdr) + sizeof (struct iphdr) + sizeof (struct icmphdr)) > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    off += sizeof (struct ethhdr);\n",
    "    iph = data + off;\n",
    "    off += sizeof (struct iphdr);\n",
    "    icmp_hdr = data + off;\n",
    "    icmp_hdr->type = ICMP_ECHOREPLY;\n",
    "    icmp_hdr->checksum += 0x0008;\n",
    "    iph->ttl = DEFAULT_TTL;\n",
    "    tmp_addr = iph->daddr;\n",
    "    iph->daddr = iph->saddr;\n",
    "    iph->saddr = tmp_addr;\n",
    "    iph->check = 0;\n",
    "    ipv4_csum_inline (iph, &csum);\n",
    "    iph->check = csum;\n",
    "    return swap_mac_and_send (data, data_end);\n",
    "}\n"
  ],
  "called_function_list": [
    "swap_mac_and_send",
    "ipv4_csum_inline"
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
__attribute__((__always_inline__)) static inline int send_icmp_reply(
    void* data,
    void* data_end) {
  struct iphdr* iph;
  struct icmphdr* icmp_hdr;
  __u32 tmp_addr = 0;
  __u64 csum = 0;
  __u64 off = 0;

  if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
       sizeof(struct icmphdr)) > data_end) {
    return XDP_DROP;
  }
  off += sizeof(struct ethhdr);
  iph = data + off;
  off += sizeof(struct iphdr);
  icmp_hdr = data + off;
  icmp_hdr->type = ICMP_ECHOREPLY;
  // the only diff between icmp echo and reply hdrs is type;
  // in first case it's 8; in second it's 0; so instead of recalc
  // checksum from ground up we will just adjust it.
  icmp_hdr->checksum += 0x0008;
  iph->ttl = DEFAULT_TTL;
  tmp_addr = iph->daddr;
  iph->daddr = iph->saddr;
  iph->saddr = tmp_addr;
  iph->check = 0;
  ipv4_csum_inline(iph, &csum);
  iph->check = csum;
  return swap_mac_and_send(data, data_end);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 92,
  "endLine": 117,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp6_reply",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int send_icmp6_reply (void *data, void *data_end)\n",
    "{\n",
    "    struct ipv6hdr *ip6h;\n",
    "    struct icmp6hdr *icmp_hdr;\n",
    "    __be32 tmp_addr [4];\n",
    "    __u64 off = 0;\n",
    "    if ((data + sizeof (struct ethhdr) + sizeof (struct ipv6hdr) + sizeof (struct icmp6hdr)) > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    off += sizeof (struct ethhdr);\n",
    "    ip6h = data + off;\n",
    "    off += sizeof (struct ipv6hdr);\n",
    "    icmp_hdr = data + off;\n",
    "    icmp_hdr->icmp6_type = ICMPV6_ECHO_REPLY;\n",
    "    icmp_hdr->icmp6_cksum -= 0x0001;\n",
    "    ip6h->hop_limit = DEFAULT_TTL;\n",
    "    memcpy (tmp_addr, ip6h->saddr.s6_addr32, 16);\n",
    "    memcpy (ip6h->saddr.s6_addr32, ip6h->daddr.s6_addr32, 16);\n",
    "    memcpy (ip6h->daddr.s6_addr32, tmp_addr, 16);\n",
    "    return swap_mac_and_send (data, data_end);\n",
    "}\n"
  ],
  "called_function_list": [
    "swap_mac_and_send",
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
__attribute__((__always_inline__)) static inline int send_icmp6_reply(
    void* data,
    void* data_end) {
  struct ipv6hdr* ip6h;
  struct icmp6hdr* icmp_hdr;
  __be32 tmp_addr[4];
  __u64 off = 0;
  if ((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
       sizeof(struct icmp6hdr)) > data_end) {
    return XDP_DROP;
  }
  off += sizeof(struct ethhdr);
  ip6h = data + off;
  off += sizeof(struct ipv6hdr);
  icmp_hdr = data + off;
  icmp_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
  // the only diff between icmp echo and reply hdrs is type;
  // in first case it's 128; in second it's 129; so instead of recalc
  // checksum from ground up we will just adjust it.
  icmp_hdr->icmp6_cksum -= 0x0001;
  ip6h->hop_limit = DEFAULT_TTL;
  memcpy(tmp_addr, ip6h->saddr.s6_addr32, 16);
  memcpy(ip6h->saddr.s6_addr32, ip6h->daddr.s6_addr32, 16);
  memcpy(ip6h->daddr.s6_addr32, tmp_addr, 16);
  return swap_mac_and_send(data, data_end);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "pkt_alter_or_redo_processing_or_interface",
      "pkt_alter_or_redo_processing_or_interface": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_TX",
          "Return": 3,
          "Description": "an efficient option to transmit the network packet out of the same NIC it just arrived on again. This is typically useful when few nodes are implementing, for example, firewalling with subsequent load balancing in a cluster and thus act as a hairpinned load balancer pushing the incoming packets back into the switch after rewriting them in XDP BPF.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_alter_or_redo_processing_or_interface"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 119,
  "endLine": 162,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp4_too_big",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_TX"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int send_icmp4_too_big (struct xdp_md *xdp)\n",
    "{\n",
    "    int headroom = (int) sizeof (struct iphdr) + (int) sizeof (struct icmphdr);\n",
    "    if (bpf_xdp_adjust_head (xdp, 0 - headroom)) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    void *data = (void *) (long) xdp->data;\n",
    "    void *data_end = (void *) (long) xdp->data_end;\n",
    "    if (data + (ICMP_TOOBIG_SIZE + headroom) > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    struct iphdr *iph, *orig_iph;\n",
    "    struct ethhdr *orig_eth;\n",
    "    struct icmphdr *icmp_hdr;\n",
    "    __u64 csum = 0;\n",
    "    __u64 off = 0;\n",
    "    orig_eth = data + headroom;\n",
    "    swap_mac (data, orig_eth);\n",
    "    off += sizeof (struct ethhdr);\n",
    "    iph = data + off;\n",
    "    off += sizeof (struct iphdr);\n",
    "    icmp_hdr = data + off;\n",
    "    off += sizeof (struct icmphdr);\n",
    "    orig_iph = data + off;\n",
    "    icmp_hdr->type = ICMP_DEST_UNREACH;\n",
    "    icmp_hdr->code = ICMP_FRAG_NEEDED;\n",
    "    icmp_hdr->un.frag.mtu = bpf_htons (MAX_PCKT_SIZE - sizeof (struct ethhdr));\n",
    "    icmp_hdr->checksum = 0;\n",
    "    ipv4_csum (icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);\n",
    "    icmp_hdr->checksum = csum;\n",
    "    iph->ttl = DEFAULT_TTL;\n",
    "    iph->daddr = orig_iph->saddr;\n",
    "    iph->saddr = orig_iph->daddr;\n",
    "    iph->version = 4;\n",
    "    iph->ihl = 5;\n",
    "    iph->protocol = IPPROTO_ICMP;\n",
    "    iph->tos = 0;\n",
    "    iph->tot_len = bpf_htons (ICMP_TOOBIG_SIZE + headroom - sizeof (struct ethhdr));\n",
    "    iph->check = 0;\n",
    "    csum = 0;\n",
    "    ipv4_csum (iph, sizeof (struct iphdr), &csum);\n",
    "    iph->check = csum;\n",
    "    return XDP_TX;\n",
    "}\n"
  ],
  "called_function_list": [
    "ipv4_csum",
    "bpf_htons",
    "swap_mac"
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
__attribute__((__always_inline__)) static inline int send_icmp4_too_big(
    struct xdp_md* xdp) {
  int headroom = (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr);
  if (bpf_xdp_adjust_head(xdp, 0 - headroom)) {
    return XDP_DROP;
  }
  void* data = (void*)(long)xdp->data;
  void* data_end = (void*)(long)xdp->data_end;
  if (data + (ICMP_TOOBIG_SIZE + headroom) > data_end) {
    return XDP_DROP;
  }
  struct iphdr *iph, *orig_iph;
  struct ethhdr* orig_eth;
  struct icmphdr* icmp_hdr;
  __u64 csum = 0;
  __u64 off = 0;
  orig_eth = data + headroom;
  swap_mac(data, orig_eth);
  off += sizeof(struct ethhdr);
  iph = data + off;
  off += sizeof(struct iphdr);
  icmp_hdr = data + off;
  off += sizeof(struct icmphdr);
  orig_iph = data + off;
  icmp_hdr->type = ICMP_DEST_UNREACH;
  icmp_hdr->code = ICMP_FRAG_NEEDED;
  icmp_hdr->un.frag.mtu = bpf_htons(MAX_PCKT_SIZE - sizeof(struct ethhdr));
  icmp_hdr->checksum = 0;
  ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
  icmp_hdr->checksum = csum;
  iph->ttl = DEFAULT_TTL;
  iph->daddr = orig_iph->saddr;
  iph->saddr = orig_iph->daddr;
  iph->version = 4;
  iph->ihl = 5;
  iph->protocol = IPPROTO_ICMP;
  iph->tos = 0;
  iph->tot_len = bpf_htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
  iph->check = 0;
  csum = 0;
  ipv4_csum(iph, sizeof(struct iphdr), &csum);
  iph->check = csum;
  return XDP_TX;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "pkt_alter_or_redo_processing_or_interface",
      "pkt_alter_or_redo_processing_or_interface": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_TX",
          "Return": 3,
          "Description": "an efficient option to transmit the network packet out of the same NIC it just arrived on again. This is typically useful when few nodes are implementing, for example, firewalling with subsequent load balancing in a cluster and thus act as a hairpinned load balancer pushing the incoming packets back into the switch after rewriting them in XDP BPF.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_alter_or_redo_processing_or_interface"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 164,
  "endLine": 203,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp6_too_big",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_TX"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int send_icmp6_too_big (struct xdp_md *xdp)\n",
    "{\n",
    "    int headroom = (int) sizeof (struct ipv6hdr) + (int) sizeof (struct icmp6hdr);\n",
    "    if (bpf_xdp_adjust_head (xdp, 0 - headroom)) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    void *data = (void *) (long) xdp->data;\n",
    "    void *data_end = (void *) (long) xdp->data_end;\n",
    "    if (data + (ICMP6_TOOBIG_SIZE + headroom) > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    struct ipv6hdr *ip6h, *orig_ip6h;\n",
    "    struct ethhdr *orig_eth;\n",
    "    struct icmp6hdr *icmp6_hdr;\n",
    "    __u64 csum = 0;\n",
    "    __u64 off = 0;\n",
    "    orig_eth = data + headroom;\n",
    "    swap_mac (data, orig_eth);\n",
    "    off += sizeof (struct ethhdr);\n",
    "    ip6h = data + off;\n",
    "    off += sizeof (struct ipv6hdr);\n",
    "    icmp6_hdr = data + off;\n",
    "    off += sizeof (struct icmp6hdr);\n",
    "    orig_ip6h = data + off;\n",
    "    ip6h->version = 6;\n",
    "    ip6h->priority = 0;\n",
    "    ip6h->nexthdr = IPPROTO_ICMPV6;\n",
    "    ip6h->hop_limit = DEFAULT_TTL;\n",
    "    ip6h->payload_len = bpf_htons (ICMP6_TOOBIG_PAYLOAD_SIZE);\n",
    "    memset (ip6h->flow_lbl, 0, sizeof (ip6h->flow_lbl));\n",
    "    memcpy (ip6h->daddr.s6_addr32, orig_ip6h->saddr.s6_addr32, 16);\n",
    "    memcpy (ip6h->saddr.s6_addr32, orig_ip6h->daddr.s6_addr32, 16);\n",
    "    icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;\n",
    "    icmp6_hdr->icmp6_code = 0;\n",
    "    icmp6_hdr->icmp6_mtu = bpf_htonl (MAX_PCKT_SIZE - sizeof (struct ethhdr));\n",
    "    icmp6_hdr->icmp6_cksum = 0;\n",
    "    ipv6_csum (icmp6_hdr, ICMP6_TOOBIG_PAYLOAD_SIZE, &csum, ip6h);\n",
    "    icmp6_hdr->icmp6_cksum = csum;\n",
    "    return XDP_TX;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "ipv6_csum",
    "memset",
    "bpf_htons",
    "bpf_htonl",
    "swap_mac"
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
__attribute__((__always_inline__)) static inline int send_icmp6_too_big(
    struct xdp_md* xdp) {
  int headroom = (int)sizeof(struct ipv6hdr) + (int)sizeof(struct icmp6hdr);
  if (bpf_xdp_adjust_head(xdp, 0 - headroom)) {
    return XDP_DROP;
  }
  void* data = (void*)(long)xdp->data;
  void* data_end = (void*)(long)xdp->data_end;
  if (data + (ICMP6_TOOBIG_SIZE + headroom) > data_end) {
    return XDP_DROP;
  }
  struct ipv6hdr *ip6h, *orig_ip6h;
  struct ethhdr* orig_eth;
  struct icmp6hdr* icmp6_hdr;
  __u64 csum = 0;
  __u64 off = 0;
  orig_eth = data + headroom;
  swap_mac(data, orig_eth);
  off += sizeof(struct ethhdr);
  ip6h = data + off;
  off += sizeof(struct ipv6hdr);
  icmp6_hdr = data + off;
  off += sizeof(struct icmp6hdr);
  orig_ip6h = data + off;
  ip6h->version = 6;
  ip6h->priority = 0;
  ip6h->nexthdr = IPPROTO_ICMPV6;
  ip6h->hop_limit = DEFAULT_TTL;
  ip6h->payload_len = bpf_htons(ICMP6_TOOBIG_PAYLOAD_SIZE);
  memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
  memcpy(ip6h->daddr.s6_addr32, orig_ip6h->saddr.s6_addr32, 16);
  memcpy(ip6h->saddr.s6_addr32, orig_ip6h->daddr.s6_addr32, 16);
  icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
  icmp6_hdr->icmp6_code = 0;
  icmp6_hdr->icmp6_mtu = bpf_htonl(MAX_PCKT_SIZE - sizeof(struct ethhdr));
  icmp6_hdr->icmp6_cksum = 0;
  ipv6_csum(icmp6_hdr, ICMP6_TOOBIG_PAYLOAD_SIZE, &csum, ip6h);
  icmp6_hdr->icmp6_cksum = csum;
  return XDP_TX;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 205,
  "endLine": 221,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp_too_big",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp",
    " bool is_ipv6",
    " int pckt_size"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int send_icmp_too_big (struct xdp_md *xdp, bool is_ipv6, int pckt_size)\n",
    "{\n",
    "    int offset = pckt_size;\n",
    "    if (is_ipv6) {\n",
    "        offset -= ICMP6_TOOBIG_SIZE;\n",
    "    }\n",
    "    else {\n",
    "        offset -= ICMP_TOOBIG_SIZE;\n",
    "    }\n",
    "    if (bpf_xdp_adjust_tail (xdp, 0 - offset)) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    if (is_ipv6) {\n",
    "        return send_icmp6_too_big (xdp);\n",
    "    }\n",
    "    else {\n",
    "        return send_icmp4_too_big (xdp);\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "send_icmp4_too_big",
    "send_icmp6_too_big"
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
__attribute__((__always_inline__)) static inline int
send_icmp_too_big(struct xdp_md* xdp, bool is_ipv6, int pckt_size) {
  int offset = pckt_size;
  if (is_ipv6) {
    offset -= ICMP6_TOOBIG_SIZE;
  } else {
    offset -= ICMP_TOOBIG_SIZE;
  }
  if (bpf_xdp_adjust_tail(xdp, 0 - offset)) {
    return XDP_DROP;
  }
  if (is_ipv6) {
    return send_icmp6_too_big(xdp);
  } else {
    return send_icmp4_too_big(xdp);
  }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
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
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 223,
  "endLine": 253,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "parse_icmpv6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " __u64 off",
    " struct packet_description *pckt"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int parse_icmpv6 (void *data, void *data_end, __u64 off, struct packet_description *pckt)\n",
    "{\n",
    "    struct icmp6hdr *icmp_hdr;\n",
    "    struct ipv6hdr *ip6h;\n",
    "    icmp_hdr = data + off;\n",
    "    if (icmp_hdr + 1 > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    if (icmp_hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {\n",
    "        return send_icmp6_reply (data, data_end);\n",
    "    }\n",
    "    if ((icmp_hdr->icmp6_type != ICMPV6_PKT_TOOBIG) && (icmp_hdr->icmp6_type != ICMPV6_DEST_UNREACH)) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    off += sizeof (struct icmp6hdr);\n",
    "    ip6h = data + off;\n",
    "    if (ip6h + 1 > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    pckt->flow.proto = ip6h->nexthdr;\n",
    "    pckt->flags |= F_ICMP;\n",
    "    memcpy (pckt->flow.srcv6, ip6h->daddr.s6_addr32, 16);\n",
    "    memcpy (pckt->flow.dstv6, ip6h->saddr.s6_addr32, 16);\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "send_icmp6_reply"
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
__attribute__((__always_inline__)) static inline int parse_icmpv6(
    void* data,
    void* data_end,
    __u64 off,
    struct packet_description* pckt) {
  struct icmp6hdr* icmp_hdr;
  struct ipv6hdr* ip6h;
  icmp_hdr = data + off;
  if (icmp_hdr + 1 > data_end) {
    return XDP_DROP;
  }
  if (icmp_hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {
    return send_icmp6_reply(data, data_end);
  }
  if ((icmp_hdr->icmp6_type != ICMPV6_PKT_TOOBIG) &&
      (icmp_hdr->icmp6_type != ICMPV6_DEST_UNREACH)) {
    return XDP_PASS;
  }
  off += sizeof(struct icmp6hdr);
  // data partition of icmp 'pkt too big' contains header (and as much data as
  // as possible) of the packet, which has trigered this icmp.
  ip6h = data + off;
  if (ip6h + 1 > data_end) {
    return XDP_DROP;
  }
  pckt->flow.proto = ip6h->nexthdr;
  pckt->flags |= F_ICMP;
  memcpy(pckt->flow.srcv6, ip6h->daddr.s6_addr32, 16);
  memcpy(pckt->flow.dstv6, ip6h->saddr.s6_addr32, 16);
  return FURTHER_PROCESSING;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
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
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 255,
  "endLine": 285,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "parse_icmp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " __u64 off",
    " struct packet_description *pckt"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int parse_icmp (void *data, void *data_end, __u64 off, struct packet_description *pckt)\n",
    "{\n",
    "    struct icmphdr *icmp_hdr;\n",
    "    struct iphdr *iph;\n",
    "    icmp_hdr = data + off;\n",
    "    if (icmp_hdr + 1 > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    if (icmp_hdr->type == ICMP_ECHO) {\n",
    "        return send_icmp_reply (data, data_end);\n",
    "    }\n",
    "    if (icmp_hdr->type != ICMP_DEST_UNREACH) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    off += sizeof (struct icmphdr);\n",
    "    iph = data + off;\n",
    "    if (iph + 1 > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    if (iph->ihl != 5) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    pckt->flow.proto = iph->protocol;\n",
    "    pckt->flags |= F_ICMP;\n",
    "    pckt->flow.src = iph->daddr;\n",
    "    pckt->flow.dst = iph->saddr;\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "called_function_list": [
    "send_icmp_reply"
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
__attribute__((__always_inline__)) static inline int parse_icmp(
    void* data,
    void* data_end,
    __u64 off,
    struct packet_description* pckt) {
  struct icmphdr* icmp_hdr;
  struct iphdr* iph;
  icmp_hdr = data + off;
  if (icmp_hdr + 1 > data_end) {
    return XDP_DROP;
  }
  if (icmp_hdr->type == ICMP_ECHO) {
    return send_icmp_reply(data, data_end);
  }
  if (icmp_hdr->type != ICMP_DEST_UNREACH) {
    return XDP_PASS;
  }
  off += sizeof(struct icmphdr);
  iph = data + off;
  if (iph + 1 > data_end) {
    return XDP_DROP;
  }
  if (iph->ihl != 5) {
    return XDP_DROP;
  }
  pckt->flow.proto = iph->protocol;
  pckt->flags |= F_ICMP;
  pckt->flow.src = iph->daddr;
  pckt->flow.dst = iph->saddr;
  return FURTHER_PROCESSING;
}
#endif // of __HANDLE_ICMP_H
