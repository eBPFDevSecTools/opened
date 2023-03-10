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

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/udp.h>

#include "bpf.h"
#include "bpf_helpers.h"

#include "encap_helpers.h"

#include "healthchecking_helpers.h"
#include "healthchecking_maps.h"
#include "healthchecking_structs.h"

SEC("tc")
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
        "opVar": "  prog_stats ",
        "inpVar": [
          " &hc_stats_map",
          " &stats_key"
        ]
      },
      {
        "opVar": "    struct hc_real_definition* real ",
        "inpVar": [
          " &hc_reals_map",
          " &somark"
        ]
      },
      {
        "opVar": "  #endif  __u32* intf_ifindex ",
        "inpVar": [
          " &hc_ctrl_map",
          " &key"
        ]
      },
      {
        "opVar": "  esrc ",
        "inpVar": [
          " &hc_pckt_macs",
          " &key"
        ]
      },
      {
        "opVar": "  edst ",
        "inpVar": [
          " &hc_pckt_macs",
          " &key"
        ]
      },
      {
        "opVar": "    __u32* hc_key_cntr_index ",
        "inpVar": [
          " &hc_key_map",
          " &hckey"
        ]
      },
      {
        "opVar": "      __u32* packets_processed_for_hc_key ",
        "inpVar": [
          "          &per_hckey_stats",
          " hc_key_cntr_index"
        ]
      }
    ],
    "bpf_redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "              return *intf_ifindex",
          " REDIRECT_EGRESS"
        ]
      }
    ]
  },
  "startLine": 34,
  "endLine": 139,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_kern.c",
  "funcName": "healthcheck_encap",
  "updateMaps": [],
  "readMaps": [
    " hc_ctrl_map",
    " per_hckey_stats",
    "  hc_pckt_macs",
    " hc_reals_map",
    " hc_key_map",
    "  hc_stats_map"
  ],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_redirect"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sched_cls",
    "lwt_xmit",
    "xdp"
  ],
  "source": [
    "int healthcheck_encap (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 stats_key = GENERIC_STATS_INDEX;\n",
    "    __u32 key = HC_MAIN_INTF_POSITION;\n",
    "    __u32 somark = skb->mark;\n",
    "    __u32 ifindex = 0;\n",
    "    __u64 flags = 0;\n",
    "    bool is_ipv6 = false;\n",
    "    int adjust_len = 0;\n",
    "    int ret = 0;\n",
    "    struct hc_stats *prog_stats;\n",
    "    struct ethhdr *ethh;\n",
    "    struct hc_mac *esrc, *edst;\n",
    "    struct hc_real_definition *src;\n",
    "    prog_stats = bpf_map_lookup_elem (& hc_stats_map, & stats_key);\n",
    "    if (!prog_stats) {\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "    if (somark == 0) {\n",
    "        prog_stats->pckts_skipped += 1;\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "    struct hc_real_definition *real = bpf_map_lookup_elem (&hc_reals_map, &somark);\n",
    "    if (!real) {\n",
    "        prog_stats->pckts_skipped += 1;\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "\n",
    "#if HC_MAX_PACKET_SIZE > 0\n",
    "    if (skb->len > HC_MAX_PACKET_SIZE) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        prog_stats->pckts_too_big += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    __u32 *intf_ifindex = bpf_map_lookup_elem (&hc_ctrl_map, &key);\n",
    "    if (!intf_ifindex) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    key = HC_SRC_MAC_POS;\n",
    "    esrc = bpf_map_lookup_elem (& hc_pckt_macs, & key);\n",
    "    if (!esrc) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    key = HC_DST_MAC_POS;\n",
    "    edst = bpf_map_lookup_elem (& hc_pckt_macs, & key);\n",
    "    if (!edst) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    if ((skb->data + sizeof (struct ethhdr)) > skb->data_end) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    ethh = (void *) (long) skb->data;\n",
    "    if (ethh->h_proto == BE_ETH_P_IPV6) {\n",
    "        is_ipv6 = true;\n",
    "    }\n",
    "    struct hc_key hckey = {}\n",
    "    ;\n",
    "    bool hc_key_parseable = set_hc_key (skb, & hckey, is_ipv6);\n",
    "    skb->mark = 0;\n",
    "    if (!HC_ENCAP(skb, real, ethh, is_ipv6)) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    if (skb->data + sizeof (struct ethhdr) > skb->data_end) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    ethh = (void *) (long) skb->data;\n",
    "    memcpy (ethh->h_source, esrc->mac, 6);\n",
    "    memcpy (ethh->h_dest, edst->mac, 6);\n",
    "    prog_stats->pckts_processed += 1;\n",
    "    if (hc_key_parseable) {\n",
    "        __u32 *hc_key_cntr_index = bpf_map_lookup_elem (&hc_key_map, &hckey);\n",
    "        if (hc_key_cntr_index) {\n",
    "            __u32 *packets_processed_for_hc_key = bpf_map_lookup_elem (&per_hckey_stats, hc_key_cntr_index);\n",
    "            if (packets_processed_for_hc_key) {\n",
    "                *packets_processed_for_hc_key += 1;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return bpf_redirect (*intf_ifindex, REDIRECT_EGRESS);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {
      "description": " Input is user accessible mirror of in-kernel sk_buff",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-08"
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
int healthcheck_encap(struct __sk_buff* skb) {
  __u32 stats_key = GENERIC_STATS_INDEX;
  __u32 key = HC_MAIN_INTF_POSITION;
  __u32 somark = skb->mark;
  __u32 ifindex = 0;
  __u64 flags = 0;
  bool is_ipv6 = false;
  int adjust_len = 0;
  int ret = 0;
  struct hc_stats* prog_stats;
  struct ethhdr* ethh;
  struct hc_mac *esrc, *edst;
  struct hc_real_definition* src;
  prog_stats = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
  if (!prog_stats) {
    return TC_ACT_UNSPEC;
  }

  if (somark == 0) {
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

  struct hc_real_definition* real = bpf_map_lookup_elem(&hc_reals_map, &somark);
  if (!real) {
    // some strange (w/ fwmark; but not a healthcheck) local packet
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

#if HC_MAX_PACKET_SIZE > 0
  if (skb->len > HC_MAX_PACKET_SIZE) {
    // do not allow packets bigger than the specified size
    prog_stats->pckts_dropped += 1;
    prog_stats->pckts_too_big += 1;
    return TC_ACT_SHOT;
  }
#endif

  __u32* intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &key);
  if (!intf_ifindex) {
    // we dont have ifindex for main interface
    // not much we can do without it. Drop packet so that hc will fail
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  key = HC_SRC_MAC_POS;
  esrc = bpf_map_lookup_elem(&hc_pckt_macs, &key);
  if (!esrc) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  key = HC_DST_MAC_POS;
  edst = bpf_map_lookup_elem(&hc_pckt_macs, &key);
  if (!edst) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  if ((skb->data + sizeof(struct ethhdr)) > skb->data_end) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  ethh = (void*)(long)skb->data;
  if (ethh->h_proto == BE_ETH_P_IPV6) {
    is_ipv6 = true;
  }

  struct hc_key hckey = {};
  bool hc_key_parseable = set_hc_key(skb, &hckey, is_ipv6);

  // to prevent recursion, if encapsulated packet would run through this filter
  skb->mark = 0;

  if (!HC_ENCAP(skb, real, ethh, is_ipv6)) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  if (skb->data + sizeof(struct ethhdr) > skb->data_end) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  ethh = (void*)(long)skb->data;
  memcpy(ethh->h_source, esrc->mac, 6);
  memcpy(ethh->h_dest, edst->mac, 6);

  prog_stats->pckts_processed += 1;

  if (hc_key_parseable) {
    __u32* hc_key_cntr_index = bpf_map_lookup_elem(&hc_key_map, &hckey);
    if (hc_key_cntr_index) {
      __u32* packets_processed_for_hc_key =
          bpf_map_lookup_elem(&per_hckey_stats, hc_key_cntr_index);
      if (packets_processed_for_hc_key) {
        *packets_processed_for_hc_key += 1;
      }
    }
  }

  return bpf_redirect(*intf_ifindex, REDIRECT_EGRESS);
}

char _license[] SEC("license") = "GPL";
