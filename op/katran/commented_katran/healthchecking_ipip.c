/* Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
 * *
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

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>

#include "bpf.h"
#include "bpf_helpers.h"

#define CTRL_MAP_SIZE 4

#ifndef REALS_MAP_SIZE
#define REALS_MAP_SIZE 4096
#endif

#define REDIRECT_EGRESS 0
#define DEFAULT_TTL 64

// Specify max packet size to avoid packets exceed mss (after encapsulation)
#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 1474
#endif

// position in stats map where we are storing generic counters.
#define GENERIC_STATS_INDEX 0

// size of stats map.
#define STATS_SIZE 1

#define NO_FLAGS 0

#define V6DADDR (1 << 0)

struct hc_real_definition {
  union {
    __be32 daddr;
    __be32 v6daddr[4];
  };
  __u8 flags;
};

// struct to record packet level for counters for relevant events
struct hc_stats {
  __u64 pckts_processed;
  __u64 pckts_dropped;
  __u64 pckts_skipped;
  __u64 pckts_too_big;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, CTRL_MAP_SIZE);
} hc_ctrl_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct hc_real_definition);
  __uint(max_entries, REALS_MAP_SIZE);
} hc_reals_map SEC(".maps");

// map which contains counters for monitoring
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct hc_stats);
  __uint(max_entries, STATS_SIZE);
  __uint(map_flags, NO_FLAGS);
} hc_stats_map SEC(".maps");

SEC("tc")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Return Type": "int",
          "Description": "Populate tunnel metadata for packet associated to skb. The tunnel metadata is set to the contents of <[ key ]>(IP: 1) , of size. The <[ flags ]>(IP: 3) can be set to a combination of the following values: BPF_F_TUNINFO_IPV6 Indicate that the tunnel is based on IPv6 protocol instead of IPv4. BPF_F_ZERO_CSUM_TX For IPv4 packets , add a flag to tunnel metadata indicating that checksum computation should be skipped and checksum set to zeroes. BPF_F_DONT_FRAGMENT Add a flag to tunnel metadata indicating that the packet should not be fragmented. BPF_F_SEQ_NUMBER Add a flag to tunnel metadata indicating that a sequence number should be added to tunnel header before sending the packet. This flag was added for GRE encapsulation , but might be used with other protocols as well in the future. Here is a typical usage on the transmit path: struct bpf_tunnel_key key; populate <[ key ]>(IP: 1) . . . bpf_skb_set_tunnel_key(skb , &key , sizeof(key) , 0); bpf_clone_redirect(skb , vxlan_dev_ifindex , 0); See also the description of the bpf_skb_get_tunnel_key() helper for additional information. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_set_tunnel_key",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  struct bpf_tunnel_key ,Var: *key}",
            "{Type:  u32 ,Var: size}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
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
        "opVar": "    __u32* v4_intf_ifindex ",
        "inpVar": [
          " &hc_ctrl_map",
          " &v4_intf_pos"
        ]
      },
      {
        "opVar": "    __u32* v6_intf_ifindex ",
        "inpVar": [
          " &hc_ctrl_map",
          " &v6_intf_pos"
        ]
      }
    ],
    "bpf_skb_set_tunnel_key": [
      {
        "opVar": "NA",
        "inpVar": [
          "  skb",
          " &tkey",
          " sizeoftkey",
          " tun_flag"
        ]
      }
    ],
    "bpf_redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "  return ifindex",
          " REDIRECT_EGRESS"
        ]
      }
    ]
  },
  "startLine": 89,
  "endLine": 157,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_ipip.c",
  "funcName": "healthcheck_encap",
  "updateMaps": [],
  "readMaps": [
    " hc_reals_map",
    "  hc_stats_map",
    " hc_ctrl_map"
  ],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "int",
  "helper": [
    "bpf_redirect",
    "bpf_map_lookup_elem",
    "bpf_skb_set_tunnel_key"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "lwt_xmit"
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
int healthcheck_encap(struct __sk_buff* skb) {
  int ret = 0;
  int tun_flag = 0;
  __u32 ifindex;
  __u32 somark = skb->mark;
  __u32 v4_intf_pos = 1;
  __u32 v6_intf_pos = 2;
  struct bpf_tunnel_key tkey = {};

  __u32 stats_key = GENERIC_STATS_INDEX;
  struct hc_stats* prog_stats;

  prog_stats = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
  if (!prog_stats) {
    return TC_ACT_UNSPEC;
  }

  if (skb->mark == 0) {
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

  struct hc_real_definition* real = bpf_map_lookup_elem(&hc_reals_map, &somark);
  if (!real) {
    // some strange (w/ fwmark; but not a healthcheck) local packet
    prog_stats->pckts_skipped += 1;
    return TC_ACT_UNSPEC;
  }

  if (skb->len > MAX_PACKET_SIZE) {
    // do not allow packets bigger than the specified size
    prog_stats->pckts_dropped += 1;
    prog_stats->pckts_too_big += 1;
    return TC_ACT_SHOT;
  }

  __u32* v4_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &v4_intf_pos);
  if (!v4_intf_ifindex) {
    // we dont have ifindex for ipip v4 interface
    // not much we can do without it. Drop packet so that hc will fail
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  __u32* v6_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &v6_intf_pos);
  if (!v6_intf_ifindex) {
    prog_stats->pckts_dropped += 1;
    return TC_ACT_SHOT;
  }

  tkey.tunnel_ttl = DEFAULT_TTL;

  // to prevent recursion, when encaped packet would run through this filter
  skb->mark = 0;

  if (real->flags == V6DADDR) {
    // the dst is v6.
    tun_flag = BPF_F_TUNINFO_IPV6;
    memcpy(tkey.remote_ipv6, real->v6daddr, 16);
    ifindex = *v6_intf_ifindex;
  } else {
    // the dst is v4
    tkey.remote_ipv4 = real->daddr;
    ifindex = *v4_intf_ifindex;
  }
  prog_stats->pckts_processed += 1;
  bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), tun_flag);
  return bpf_redirect(ifindex, REDIRECT_EGRESS);
}

char _license[] SEC("license") = "GPL";
