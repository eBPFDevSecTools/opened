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

/*
 OPENED COMMENT BEGIN
 File: /home/sayandes/codequery/katran/healthchecking_ipip.c
 Startline: 88
 Endline: 157
 Funcname: healthcheck_encap
 Input: (struct __sk_buff *skb)
 Output: int
 Helpers: [bpf_redirect,bpf_skb_set_tunnel_key,bpf_map_lookup_elem,]
 Read_maps: [ hc_ctrl_map, hc_reals_map, hc_stats_map,]
 Update_maps: []
 Func Description: Performs healthcheck for ip-in-ip encapsulated packets.
                   Use default action configured from tc (TC_ACT_UNSPEC), which is skip the packet, if 
                   1) program stats is NULL/stats_key is not found in hc_stats_map, 
                   2)mark of the sk_buff is 0, 
                   3)somark is not found in hc_reals_map
                   The program returns error/healthcheck fails (TC_ACT_SHOT) if 
                   1)packet is bigger than the specified size,
                   2)do not have ipip v4 or v6 ifindex for main interface.
                   Otherwise, Populate tunnel metadata for packet associated to skb, the tunnel metadata is set to the contents of tkey.
                   The packet passes the healthcheck, and will be redirected to another net device of index intf_ifindex.

 OPENED COMMENT END
 */
SEC("tc")
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
  
  //The cilium is not aware of this flow as it doesn't have any information on it in its map.
  prog_stats = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
  if (!prog_stats) {
    return TC_ACT_UNSPEC;
  }
  
  //The cilium modules before have not placed any marks and for cilium controlled packets, mark should be set. So the cilium doesn't know what to do.
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
