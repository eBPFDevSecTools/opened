/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
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

#ifndef __HEALTHCHECKING_HELPERS_H
#define __HEALTHCHECKING_HELPERS_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include "bpf.h"
#include "bpf_helpers.h"

#include "encap_helpers.h"

#include "healthchecking_maps.h"
#include "healthchecking_structs.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 37,
  "endLine": 77,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h",
  "Funcname": "set_hc_key",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "const struct  __sk_buff *skb",
    " struct hc_key *hckey",
    " bool is_ipv6"
  ],
  "Output": "staticinlinebool",
  "Helper": "",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline bool
set_hc_key(const struct __sk_buff* skb, struct hc_key* hckey, bool is_ipv6) {
  void* iphdr = (void*)(long)skb->data + sizeof(struct ethhdr);
  void* transport_hdr;

  if (is_ipv6) {
    struct ipv6hdr* ip6h = iphdr;
    if (ip6h + 1 > (void*)(long)skb->data_end) {
      return false;
    }
    transport_hdr = iphdr + sizeof(struct ipv6hdr);
    memcpy(hckey->addrv6, ip6h->daddr.s6_addr32, 16);
    hckey->proto = ip6h->nexthdr;
  } else {
    struct iphdr* iph = iphdr;
    if (iph + 1 > (void*)(long)skb->data_end) {
      return false;
    }
    transport_hdr = iphdr + sizeof(struct iphdr);
    hckey->addr = iph->daddr;
    hckey->proto = iph->protocol;
  }

  if (hckey->proto == IPPROTO_TCP) {
    struct tcphdr* tcp = transport_hdr;
    if (tcp + 1 > (void*)(long)skb->data_end) {
      return false;
    }
    hckey->port = tcp->dest;
  } else if (hckey->proto == IPPROTO_UDP) {
    struct udphdr* udp = transport_hdr;
    if (udp + 1 > (void*)(long)skb->data_end) {
      return false;
    }
    hckey->port = udp->dest;
  } else {
    return false;
  }

  return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "update_pkt": [
        {
          "Description": "Grow or shrink the room for data in the packet associated to <[ skb ]>(IP: 0) by <[ len_diff ]>(IP: 1) , and according to the selected mode. There is a single supported <[ mode ]>(IP: 2) at this time:BPF_ADJ_ROOM_NET: Adjust room at the network layer (room space is added or removed below the layer 3 header). All values for <[ flags ]>(IP: 3) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlaying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": "0 on success, or a negative error in case of failure.",
          "Return Type": "int",
          "Function Name": "bpf_skb_adjust_room",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len_diff}",
            "{Type:  u32 ,Var: mode}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    },
    {
      "map_read": [
        {
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": "Map value associated to key, or NULL if no entry was found.",
          "Return Type": "void",
          "Function Name": "*bpf_map_lookup_elem",
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
      "{\n \"opVar\": \"    src \",\n \"inpVar\": [\n  \" &hc_pckt_srcs_map\",\n  \" &key\"\n ]\n}",
      "{\n \"opVar\": \"    src \",\n \"inpVar\": [\n  \" &hc_pckt_srcs_map\",\n  \" &key\"\n ]\n}"
    ],
    "bpf_skb_adjust_room": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"        if skb\",\n  \" adjust_len\",\n  \" BPF_ADJ_ROOM_MAC\",\n  \" flags \"\n ]\n}",
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"        if skb\",\n  \" adjust_len\",\n  \" BPF_ADJ_ROOM_MAC\",\n  \" flags \"\n ]\n}"
    ]
  },
  "startLine": 79,
  "endLine": 139,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h",
  "Funcname": "hc_encap_ipip",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    "  hc_pckt_srcs_map",
    ""
  ],
  "Input": [
    "struct  __sk_buff *skb",
    " struct hc_real_definition *real",
    " struct ethhdr *ethh",
    " bool is_ipv6"
  ],
  "Output": "staticinlinebool",
  "Helper": "bpf_map_lookup_elem,bpf_skb_adjust_room,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline bool hc_encap_ipip(
    struct __sk_buff* skb,
    struct hc_real_definition* real,
    struct ethhdr* ethh,
    bool is_ipv6) {
  struct hc_real_definition* src;
  __u64 flags = 0;
  __u16 pkt_len;
  int adjust_len;
  __u32 key;

  pkt_len = skb->len - sizeof(struct ethhdr);

  if (real->flags == V6DADDR) {
    __u8 proto = IPPROTO_IPV6;
    key = V6_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
    adjust_len = sizeof(struct ipv6hdr);
    // new header would be inserted after MAC but before old L3 header
    if (bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) >
        skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IPV6;

    struct ipv6hdr* ip6h = (void*)(long)skb->data + sizeof(struct ethhdr);
    if (!is_ipv6) {
      proto = IPPROTO_IPIP;
    }
    create_v6_hdr(
        ip6h, DEFAULT_TOS, src->v6daddr, real->v6daddr, pkt_len, proto);
  } else {
    key = V4_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
    adjust_len = sizeof(struct iphdr);
    // new header would be inserted after MAC but before old L3 header
    if (bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr)) >
        skb->data_end) {
      return false;
    }
    struct iphdr* iph = (void*)(long)skb->data + sizeof(struct ethhdr);
    create_v4_hdr(
        iph, DEFAULT_TOS, src->daddr, real->daddr, pkt_len, IPPROTO_IPIP);
  }
  return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 141,
  "endLine": 143,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h",
  "Funcname": "gue_sport",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "__u32 seed"
  ],
  "Output": "staticinline__u16",
  "Helper": "",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline __u16 gue_sport(__u32 seed) {
  return (__u16)((seed ^ (seed >> 16)) & 0xFFFF);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "update_pkt": [
        {
          "Description": "Grow or shrink the room for data in the packet associated to <[ skb ]>(IP: 0) by <[ len_diff ]>(IP: 1) , and according to the selected mode. There is a single supported <[ mode ]>(IP: 2) at this time:BPF_ADJ_ROOM_NET: Adjust room at the network layer (room space is added or removed below the layer 3 header). All values for <[ flags ]>(IP: 3) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlaying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": "0 on success, or a negative error in case of failure.",
          "Return Type": "int",
          "Function Name": "bpf_skb_adjust_room",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len_diff}",
            "{Type:  u32 ,Var: mode}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    },
    {
      "map_read": [
        {
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": "Map value associated to key, or NULL if no entry was found.",
          "Return Type": "void",
          "Function Name": "*bpf_map_lookup_elem",
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
      "{\n \"opVar\": \"    src \",\n \"inpVar\": [\n  \" &hc_pckt_srcs_map\",\n  \" &key\"\n ]\n}",
      "{\n \"opVar\": \"    src \",\n \"inpVar\": [\n  \" &hc_pckt_srcs_map\",\n  \" &key\"\n ]\n}"
    ],
    "bpf_skb_adjust_room": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"        if skb\",\n  \" adjust_len\",\n  \" BPF_ADJ_ROOM_MAC\",\n  \" flags \"\n ]\n}",
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"        if skb\",\n  \" adjust_len\",\n  \" BPF_ADJ_ROOM_MAC\",\n  \" flags \"\n ]\n}"
    ]
  },
  "startLine": 145,
  "endLine": 213,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h",
  "Funcname": "hc_encap_gue",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    "  hc_pckt_srcs_map",
    ""
  ],
  "Input": [
    "struct  __sk_buff *skb",
    " struct hc_real_definition *real",
    " struct ethhdr *ethh",
    " bool is_ipv6"
  ],
  "Output": "staticinlinebool",
  "Helper": "bpf_map_lookup_elem,bpf_skb_adjust_room,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
__attribute__((__always_inline__)) static inline bool hc_encap_gue(
    struct __sk_buff* skb,
    struct hc_real_definition* real,
    struct ethhdr* ethh,
    bool is_ipv6) {
  struct hc_real_definition* src;
  __u64 flags = 0;
  __u16 pkt_len;
  __u16 sport;
  int adjust_len;
  __u32 key;

  pkt_len = skb->len - sizeof(struct ethhdr);

  if (real->flags == V6DADDR) {
    sport = gue_sport(real->v6daddr[0] | real->v6daddr[3]);
    __u8 proto = IPPROTO_IPV6;
    key = V6_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 |
        BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    adjust_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr);
    // new headers would be inserted after MAC but before old L3 header
    if (bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
         sizeof(struct udphdr)) > skb->data_end) {
      return false;
    }
    ethh = (void*)(long)skb->data;
    ethh->h_proto = BE_ETH_P_IPV6;

    struct ipv6hdr* ip6h = (void*)(long)skb->data + sizeof(struct ethhdr);
    struct udphdr* udph = (void*)ip6h + sizeof(struct ipv6hdr);
    pkt_len += sizeof(struct udphdr);
    create_udp_hdr(udph, sport, GUE_DPORT, pkt_len, GUE_CSUM);
    create_v6_hdr(
        ip6h, DEFAULT_TOS, src->v6daddr, real->v6daddr, pkt_len, IPPROTO_UDP);
  } else {
    sport = gue_sport(real->daddr);
    key = V4_SRC_INDEX;
    src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
    if (!src) {
      return false;
    }
    flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
        BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    adjust_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    // new headers would be inserted after MAC but before old L3 header
    if (bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
      return false;
    }
    if ((skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
         sizeof(struct udphdr)) > skb->data_end) {
      return false;
    }
    struct iphdr* iph = (void*)(long)skb->data + sizeof(struct ethhdr);
    struct udphdr* udph = (void*)iph + sizeof(struct iphdr);
    pkt_len += sizeof(struct udphdr);
    create_udp_hdr(udph, sport, GUE_DPORT, pkt_len, GUE_CSUM);
    create_v4_hdr(
        iph, DEFAULT_TOS, src->daddr, real->daddr, pkt_len, IPPROTO_UDP);
  }
  return true;
}

#endif // of __HEALTHCHECKING_HELPERS_H
