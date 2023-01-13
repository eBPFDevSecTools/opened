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
  "capability": [
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
    },
    {
      "pkt_stop_processing_drop_packet": [
        {
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\"."
        }
      ]
    },
    {
      "pkt_go_to_next_module": [
        {
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_UNSPEC",
          "Return": -1,
          "Description": "unspecified action and is used in three cases, i) when an offloaded tc BPF program is attached and the tc ingress hook is run where the cls_bpf representation for the offloaded program will return TC_ACT_UNSPEC, ii) in order to continue with the next tc BPF program in cls_bpf for the multi-program case. The latter also works in combination with offloaded tc BPF programs from point i) where the TC_ACT_UNSPEC from there continues with a next tc BPF program solely running in non-offloaded case. Last but not least, iii) TC_ACT_UNSPEC is also used for the single program case to simply tell the kernel to continue with the skb without additional side-effects. TC_ACT_UNSPEC is very similar to the TC_ACT_OK action code in the sense that both pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. The only difference to TC_ACT_OK is that TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context."
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      "{\n \"opVar\": \"  prog_stats \",\n \"inpVar\": [\n  \" &hc_stats_map\",\n  \" &stats_key\"\n ]\n}",
      "{\n \"opVar\": \"    struct hc_real_definition* real \",\n \"inpVar\": [\n  \" &hc_reals_map\",\n  \" &somark\"\n ]\n}",
      "{\n \"opVar\": \"  #endif  __u32* intf_ifindex \",\n \"inpVar\": [\n  \" &hc_ctrl_map\",\n  \" &key\"\n ]\n}",
      "{\n \"opVar\": \"  esrc \",\n \"inpVar\": [\n  \" &hc_pckt_macs\",\n  \" &key\"\n ]\n}",
      "{\n \"opVar\": \"  edst \",\n \"inpVar\": [\n  \" &hc_pckt_macs\",\n  \" &key\"\n ]\n}",
      "{\n \"opVar\": \"    __u32* hc_key_cntr_index \",\n \"inpVar\": [\n  \" &hc_key_map\",\n  \" &hckey\"\n ]\n}",
      "{\n \"opVar\": \"      __u32* packets_processed_for_hc_key \",\n \"inpVar\": [\n  \"          &per_hckey_stats\",\n  \" hc_key_cntr_index\"\n ]\n}"
    ],
    "bpf_redirect": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"              return *intf_ifindex\",\n  \" REDIRECT_EGRESS\"\n ]\n}"
    ]
  },
  "startLine": 34,
  "endLine": 139,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_kern.c",
  "Funcname": "healthcheck_encap",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    " per_hckey_stats",
    "  hc_pckt_macs",
    " hc_ctrl_map",
    " hc_key_map",
    "  hc_stats_map",
    " hc_reals_map",
    ""
  ],
  "Input": [
    "struct  __sk_buff *skb"
  ],
  "Output": "int",
  "Helper": "bpf_redirect,bpf_map_lookup_elem,",
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
