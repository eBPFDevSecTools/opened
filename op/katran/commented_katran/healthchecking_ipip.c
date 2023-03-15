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
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Populate tunnel metadata for packet associated to skb. The tunnel metadata is set to the contents of <[ key ]>(IP: 1) , of size. The <[ flags ]>(IP: 3) can be set to a combination of the following values: BPF_F_TUNINFO_IPV6 Indicate that the tunnel is based on IPv6 protocol instead of IPv4. BPF_F_ZERO_CSUM_TX For IPv4 packets , add a flag to tunnel metadata indicating that checksum computation should be skipped and checksum set to zeroes. BPF_F_DONT_FRAGMENT Add a flag to tunnel metadata indicating that the packet should not be fragmented. BPF_F_SEQ_NUMBER Add a flag to tunnel metadata indicating that a sequence number should be added to tunnel header before sending the packet. This flag was added for GRE encapsulation , but might be used with other protocols as well in the future. Here is a typical usage on the transmit path: struct bpf_tunnel_key key; populate <[ key ]>(IP: 1) . . . bpf_skb_set_tunnel_key(skb , &key , sizeof(key) , 0); bpf_clone_redirect(skb , vxlan_dev_ifindex , 0); See also the description of the bpf_skb_get_tunnel_key() helper for additional information. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_set_tunnel_key",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  struct bpf_tunnel_key ,Var: *key}",
            "{Type:  u32 ,Var: size}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    },
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
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    },
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
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
          "Function Name": "TC_ACT_UNSPEC",
          "Return": -1,
          "Description": "unspecified action and is used in three cases, i) when an offloaded tc BPF program is attached and the tc ingress hook is run where the cls_bpf representation for the offloaded program will return TC_ACT_UNSPEC, ii) in order to continue with the next tc BPF program in cls_bpf for the multi-program case. The latter also works in combination with offloaded tc BPF programs from point i) where the TC_ACT_UNSPEC from there continues with a next tc BPF program solely running in non-offloaded case. Last but not least, iii) TC_ACT_UNSPEC is also used for the single program case to simply tell the kernel to continue with the skb without additional side-effects. TC_ACT_UNSPEC is very similar to the TC_ACT_OK action code in the sense that both pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. The only difference to TC_ACT_OK is that TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 89,
  "endLine": 157,
  "File": "/home/sayandes/opened_extraction/examples/katran/healthchecking_ipip.c",
  "funcName": "healthcheck_encap",
  "developer_inline_comments": [],
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
    "bpf_skb_set_tunnel_key",
    "bpf_map_lookup_elem",
    "TC_ACT_SHOT",
    "bpf_redirect",
    "TC_ACT_UNSPEC"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "int healthcheck_encap (struct  __sk_buff *skb)\n",
    "{\n",
    "    int ret = 0;\n",
    "    int tun_flag = 0;\n",
    "    __u32 ifindex;\n",
    "    __u32 somark = skb->mark;\n",
    "    __u32 v4_intf_pos = 1;\n",
    "    __u32 v6_intf_pos = 2;\n",
    "    struct bpf_tunnel_key tkey = {}\n",
    "    ;\n",
    "    __u32 stats_key = GENERIC_STATS_INDEX;\n",
    "    struct hc_stats *prog_stats;\n",
    "    prog_stats = bpf_map_lookup_elem (& hc_stats_map, & stats_key);\n",
    "    if (!prog_stats) {\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "    if (skb->mark == 0) {\n",
    "        prog_stats->pckts_skipped += 1;\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "    struct hc_real_definition *real = bpf_map_lookup_elem (&hc_reals_map, &somark);\n",
    "    if (!real) {\n",
    "        prog_stats->pckts_skipped += 1;\n",
    "        return TC_ACT_UNSPEC;\n",
    "    }\n",
    "    if (skb->len > MAX_PACKET_SIZE) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        prog_stats->pckts_too_big += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    __u32 *v4_intf_ifindex = bpf_map_lookup_elem (&hc_ctrl_map, &v4_intf_pos);\n",
    "    if (!v4_intf_ifindex) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    __u32 *v6_intf_ifindex = bpf_map_lookup_elem (&hc_ctrl_map, &v6_intf_pos);\n",
    "    if (!v6_intf_ifindex) {\n",
    "        prog_stats->pckts_dropped += 1;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    tkey.tunnel_ttl = DEFAULT_TTL;\n",
    "    skb->mark = 0;\n",
    "    if (real->flags == V6DADDR) {\n",
    "        tun_flag = BPF_F_TUNINFO_IPV6;\n",
    "        memcpy (tkey.remote_ipv6, real->v6daddr, 16);\n",
    "        ifindex = *v6_intf_ifindex;\n",
    "    }\n",
    "    else {\n",
    "        tkey.remote_ipv4 = real->daddr;\n",
    "        ifindex = *v4_intf_ifindex;\n",
    "    }\n",
    "    prog_stats->pckts_processed += 1;\n",
    "    bpf_skb_set_tunnel_key (skb, &tkey, sizeof (tkey), tun_flag);\n",
    "    return bpf_redirect (ifindex, REDIRECT_EGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "HC_ENCAP",
    "memcpy",
    "set_hc_key"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " Performs healthcheck for ip-in-ip encapsulated packets.                   Use default action configured from tc (TC_ACT_UNSPEC), which is skip the packet, if                    1) program stats is NULL/stats_key is not found in hc_stats_map,                    2)mark of the sk_buff is 0,                    3)somark is not found in hc_reals_map                   The program returns error/healthcheck fails (TC_ACT_SHOT) if                    1)packet is bigger than the specified size,                   2)do not have ipip v4 or v6 ifindex for main interface.                   Otherwise, Populate tunnel metadata for packet associated to skb, the tunnel metadata is set to the contents of tkey.                   The packet passes the healthcheck, and will be redirected to another net device of index intf_ifindex. ",
      "author": "Qintian Huang",
      "authorEmail": "qthuang@bu.edu",
      "date": "2023-02-24"
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
