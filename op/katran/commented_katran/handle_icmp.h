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
  "capability": [],
  "helperCallParams": {},
  "startLine": 38,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "swap_mac_and_send",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 58,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "swap_mac",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " struct ethhdr *orig_eth"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 60,
  "endLine": 90,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 92,
  "endLine": 117,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp6_reply",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
  "capability": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_xdp_adjust_head": [
      {
        "opVar": "NA",
        "inpVar": [
          "  if xdp",
          " 0 - headroom "
        ]
      }
    ]
  },
  "startLine": 119,
  "endLine": 162,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp4_too_big",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "capability": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_xdp_adjust_head": [
      {
        "opVar": "NA",
        "inpVar": [
          "  if xdp",
          " 0 - headroom "
        ]
      }
    ]
  },
  "startLine": 164,
  "endLine": 203,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp6_too_big",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "capability": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data_end by <[ delta ]>(IP: 1) bytes. It is only possible to shrink the packet as of this writing , therefore <[ delta ]>(IP: 1) must be a negative integer. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_tail",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_xdp_adjust_tail": [
      {
        "opVar": "NA",
        "inpVar": [
          "    if xdp",
          " 0 - offset "
        ]
      }
    ]
  },
  "startLine": 205,
  "endLine": 221,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "send_icmp_too_big",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *xdp",
    " bool is_ipv6",
    " int pckt_size"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_xdp_adjust_tail"
  ],
  "compatibleHookpoints": [
    "xdp"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 223,
  "endLine": 253,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "parse_icmpv6",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " __u64 off",
    " struct packet_description *pckt"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 255,
  "endLine": 285,
  "File": "/home/sayandes/opened_extraction/examples/katran/handle_icmp.h",
  "funcName": "parse_icmp",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " void *data_end",
    " __u64 off",
    " struct packet_description *pckt"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
