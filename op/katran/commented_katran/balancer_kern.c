/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "balancer_consts.h"
#include "balancer_helpers.h"
#include "balancer_maps.h"
#include "balancer_structs.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "handle_icmp.h"
#include "jhash.h"
#include "pckt_encap.h"
#include "pckt_parsing.h"

__attribute__((__always_inline__)) 
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
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "  struct lb_stats* conn_rate_stats ",
        "inpVar": [
          "      &stats",
          " &conn_rate_key"
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "    *cur_time ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 25,
  "endLine": 50,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "is_under_flood",
  "updateMaps": [],
  "readMaps": [
    " stats"
  ],
  "input": [
    "__u64 *cur_time"
  ],
  "output": "staticinlinebool",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "tracepoint",
    "sk_skb",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline bool is_under_flood (__u64 *cur_time)\n",
    "{\n",
    "    __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;\n",
    "    struct lb_stats *conn_rate_stats = bpf_map_lookup_elem (&stats, &conn_rate_key);\n",
    "    if (!conn_rate_stats) {\n",
    "        return true;\n",
    "    }\n",
    "    *cur_time = bpf_ktime_get_ns ();\n",
    "    if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {\n",
    "        conn_rate_stats->v1 = 1;\n",
    "        conn_rate_stats->v2 = *cur_time;\n",
    "    }\n",
    "    else {\n",
    "        conn_rate_stats->v1 += 1;\n",
    "        if (conn_rate_stats->v1 > MAX_CONN_RATE) {\n",
    "            return true;\n",
    "        }\n",
    "    }\n",
    "    return false;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Check how many connection have been made within the last one second(or other predefined value), function will return true if it's exceding the max connection rate and false otherwise. ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
	static inline bool is_under_flood(
    __u64* cur_time) {
  __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
  struct lb_stats* conn_rate_stats =
      bpf_map_lookup_elem(&stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__always_inline__)) 
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
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "      lpm_val ",
        "inpVar": [
          " &lpm_src_v6",
          " &lpm_key_v6"
        ]
      },
      {
        "opVar": "      lpm_val ",
        "inpVar": [
          " &lpm_src_v4",
          " &lpm_key_v4"
        ]
      },
      {
        "opVar": "    struct lb_stats* data_stats ",
        "inpVar": [
          " &stats",
          " &stats_key"
        ]
      },
      {
        "opVar": "    real_pos ",
        "inpVar": [
          " &ch_rings",
          " &key"
        ]
      },
      {
        "opVar": "  *real ",
        "inpVar": [
          " &reals",
          " &key"
        ]
      }
    ],
    "bpf_map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "    lru_map",
          " &pckt->flow",
          " &new_dst_lru",
          " BPF_ANY"
        ]
      }
    ]
  },
  "startLine": 53,
  "endLine": 131,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "get_packet_dst",
  "updateMaps": [
    " lru_map"
  ],
  "readMaps": [
    "  lpm_src_v6",
    "  lpm_src_v4",
    " reals",
    "  ch_rings",
    " stats"
  ],
  "input": [
    "struct real_definition **real",
    " struct packet_description *pckt",
    " struct vip_meta *vip_info",
    " bool is_ipv6",
    " void *lru_map"
  ],
  "output": "staticinlinebool",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "tracepoint",
    "sk_skb",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline bool get_packet_dst (struct real_definition **real, struct packet_description *pckt, struct vip_meta *vip_info, bool is_ipv6, void *lru_map)\n",
    "{\n",
    "    struct real_pos_lru new_dst_lru = {}\n",
    "    ;\n",
    "    bool under_flood = false;\n",
    "    bool src_found = false;\n",
    "    __u32 *real_pos;\n",
    "    __u64 cur_time = 0;\n",
    "    __u32 hash;\n",
    "    __u32 key;\n",
    "    under_flood = is_under_flood (& cur_time);\n",
    "\n",
    "#ifdef LPM_SRC_LOOKUP\n",
    "    if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {\n",
    "        __u32 *lpm_val;\n",
    "        if (is_ipv6) {\n",
    "            struct v6_lpm_key lpm_key_v6 = {}\n",
    "            ;\n",
    "            lpm_key_v6.prefixlen = 128;\n",
    "            memcpy (lpm_key_v6.addr, pckt->flow.srcv6, 16);\n",
    "            lpm_val = bpf_map_lookup_elem (& lpm_src_v6, & lpm_key_v6);\n",
    "        }\n",
    "        else {\n",
    "            struct v4_lpm_key lpm_key_v4 = {}\n",
    "            ;\n",
    "            lpm_key_v4.addr = pckt->flow.src;\n",
    "            lpm_key_v4.prefixlen = 32;\n",
    "            lpm_val = bpf_map_lookup_elem (& lpm_src_v4, & lpm_key_v4);\n",
    "        }\n",
    "        if (lpm_val) {\n",
    "            src_found = true;\n",
    "            key = *lpm_val;\n",
    "        }\n",
    "        __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;\n",
    "        struct lb_stats *data_stats = bpf_map_lookup_elem (&stats, &stats_key);\n",
    "        if (data_stats) {\n",
    "            if (src_found) {\n",
    "                data_stats->v2 += 1;\n",
    "            }\n",
    "            else {\n",
    "                data_stats->v1 += 1;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (!src_found) {\n",
    "        bool hash_16bytes = is_ipv6;\n",
    "        if (vip_info->flags & F_HASH_DPORT_ONLY) {\n",
    "            pckt->flow.port16[0] = pckt->flow.port16[1];\n",
    "            memset (pckt->flow.srcv6, 0, 16);\n",
    "        }\n",
    "        hash = get_packet_hash (pckt, hash_16bytes) % RING_SIZE;\n",
    "        key = RING_SIZE * (vip_info->vip_num) + hash;\n",
    "        real_pos = bpf_map_lookup_elem (& ch_rings, & key);\n",
    "        if (!real_pos) {\n",
    "            return false;\n",
    "        }\n",
    "        key = *real_pos;\n",
    "    }\n",
    "    pckt->real_index = key;\n",
    "    *real = bpf_map_lookup_elem (&reals, &key);\n",
    "    if (!(*real)) {\n",
    "        return false;\n",
    "    }\n",
    "    if (lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood) {\n",
    "        if (pckt->flow.proto == IPPROTO_UDP) {\n",
    "            new_dst_lru.atime = cur_time;\n",
    "        }\n",
    "        new_dst_lru.pos = key;\n",
    "        bpf_map_update_elem (lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);\n",
    "    }\n",
    "    return true;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " This function checks the source routing for new connections. ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
	static inline bool get_packet_dst(
    struct real_definition** real,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6,
    void* lru_map) {
  // to update lru w/ new connection
  struct real_pos_lru new_dst_lru = {};
  bool under_flood = false;
  bool src_found = false;
  __u32* real_pos;
  __u64 cur_time = 0;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

#ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
    __u32* lpm_val;
    if (is_ipv6) {
      struct v6_lpm_key lpm_key_v6 = {};
      lpm_key_v6.prefixlen = 128;
      memcpy(lpm_key_v6.addr, pckt->flow.srcv6, 16);
      lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
    } else {
      struct v4_lpm_key lpm_key_v4 = {};
      lpm_key_v4.addr = pckt->flow.src;
      lpm_key_v4.prefixlen = 32;
      lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
    }
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
#endif
  if (!src_found) {
    bool hash_16bytes = is_ipv6;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;

    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if (!real_pos) {
      return false;
    }
    key = *real_pos;
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    return false;
  }
  if (lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
    if (pckt->flow.proto == IPPROTO_UDP) {
      new_dst_lru.atime = cur_time;
    }
    new_dst_lru.pos = key;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  }
  return true;
}

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
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "  dst_lru ",
        "inpVar": [
          " lru_map",
          " &pckt->flow"
        ]
      },
      {
        "opVar": "  *real ",
        "inpVar": [
          " &reals",
          " &key"
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "    cur_time ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 133,
  "endLine": 156,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "connection_table_lookup",
  "updateMaps": [],
  "readMaps": [
    " lru_map",
    " reals"
  ],
  "input": [
    "struct real_definition **real",
    " struct packet_description *pckt",
    " void *lru_map",
    " bool isGlobalLru"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "tracepoint",
    "sk_skb",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline void connection_table_lookup (struct real_definition **real, struct packet_description *pckt, void *lru_map, bool isGlobalLru)\n",
    "{\n",
    "    struct real_pos_lru *dst_lru;\n",
    "    __u64 cur_time;\n",
    "    __u32 key;\n",
    "    dst_lru = bpf_map_lookup_elem (lru_map, & pckt -> flow);\n",
    "    if (!dst_lru) {\n",
    "        return;\n",
    "    }\n",
    "    if (!isGlobalLru && pckt->flow.proto == IPPROTO_UDP) {\n",
    "        cur_time = bpf_ktime_get_ns ();\n",
    "        if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {\n",
    "            return;\n",
    "        }\n",
    "        dst_lru->atime = cur_time;\n",
    "    }\n",
    "    key = dst_lru->pos;\n",
    "    pckt->real_index = key;\n",
    "    *real = bpf_map_lookup_elem (&reals, &key);\n",
    "    return;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " First check if the packet flow exists in lru_map and whether this connection is legal regarding its connection time(only check this if it is UDP protocol). Then we update the input real using the info from reals ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline void connection_table_lookup(
    struct real_definition** real,
    struct packet_description* pckt,
    void* lru_map,
    bool isGlobalLru) {
  struct real_pos_lru* dst_lru;
  __u64 cur_time;
  __u32 key;
  dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
  if (!dst_lru) {
    return;
  }
  if (!isGlobalLru && pckt->flow.proto == IPPROTO_UDP) {
    cur_time = bpf_ktime_get_ns();
    if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
      return;
    }
    dst_lru->atime = cur_time;
  }
  key = dst_lru->pos;
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  return;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 158,
  "endLine": 230,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "process_l3_headers",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct packet_description *pckt",
    " __u8 *protocol",
    " __u64 off",
    " __u16 *pkt_bytes",
    " void *data",
    " void *data_end",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int process_l3_headers (struct packet_description *pckt, __u8 *protocol, __u64 off, __u16 *pkt_bytes, void *data, void *data_end, bool is_ipv6)\n",
    "{\n",
    "    __u64 iph_len;\n",
    "    int action;\n",
    "    struct iphdr *iph;\n",
    "    struct ipv6hdr *ip6h;\n",
    "    if (is_ipv6) {\n",
    "        ip6h = data + off;\n",
    "        if (ip6h + 1 > data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        iph_len = sizeof (struct ipv6hdr);\n",
    "        *protocol = ip6h->nexthdr;\n",
    "        pckt->flow.proto = *protocol;\n",
    "        pckt->tos = (ip6h->priority << 4) & 0xF0;\n",
    "        pckt->tos = pckt->tos | ((ip6h->flow_lbl[0] >> 4) & 0x0F);\n",
    "        *pkt_bytes = bpf_ntohs (ip6h->payload_len);\n",
    "        off += iph_len;\n",
    "        if (*protocol == IPPROTO_FRAGMENT) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        else if (*protocol == IPPROTO_ICMPV6) {\n",
    "            action = parse_icmpv6 (data, data_end, off, pckt);\n",
    "            if (action >= 0) {\n",
    "                return action;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            memcpy (pckt->flow.srcv6, ip6h->saddr.s6_addr32, 16);\n",
    "            memcpy (pckt->flow.dstv6, ip6h->daddr.s6_addr32, 16);\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        iph = data + off;\n",
    "        if (iph + 1 > data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        if (iph->ihl != 5) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        pckt->tos = iph->tos;\n",
    "        *protocol = iph->protocol;\n",
    "        pckt->flow.proto = *protocol;\n",
    "        *pkt_bytes = bpf_ntohs (iph->tot_len);\n",
    "        off += IPV4_HDR_LEN_NO_OPT;\n",
    "        if (iph->frag_off & PCKT_FRAGMENTED) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        if (*protocol == IPPROTO_ICMP) {\n",
    "            action = parse_icmp (data, data_end, off, pckt);\n",
    "            if (action >= 0) {\n",
    "                return action;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            pckt->flow.src = iph->saddr;\n",
    "            pckt->flow.dst = iph->daddr;\n",
    "        }\n",
    "    }\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Function processes the packet based on protocol and stores information in packet_description structure  ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int process_l3_headers(
    struct packet_description* pckt,
    __u8* protocol,
    __u64 off,
    __u16* pkt_bytes,
    void* data,
    void* data_end,
    bool is_ipv6) {
  __u64 iph_len;
  int action;
  struct iphdr* iph;
  struct ipv6hdr* ip6h;
  if (is_ipv6) {
    ip6h = data + off;
    if (ip6h + 1 > data_end) {
      return XDP_DROP;
    }

    iph_len = sizeof(struct ipv6hdr);
    *protocol = ip6h->nexthdr;
    pckt->flow.proto = *protocol;

    // copy tos from the packet
    pckt->tos = (ip6h->priority << 4) & 0xF0;
    pckt->tos = pckt->tos | ((ip6h->flow_lbl[0] >> 4) & 0x0F);

    *pkt_bytes = bpf_ntohs(ip6h->payload_len);
    off += iph_len;
    if (*protocol == IPPROTO_FRAGMENT) {
      // we drop fragmented packets
      return XDP_DROP;
    } else if (*protocol == IPPROTO_ICMPV6) {
      action = parse_icmpv6(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
    } else {
      memcpy(pckt->flow.srcv6, ip6h->saddr.s6_addr32, 16);
      memcpy(pckt->flow.dstv6, ip6h->daddr.s6_addr32, 16);
    }
  } else {
    iph = data + off;
    if (iph + 1 > data_end) {
      return XDP_DROP;
    }
    // ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5) {
      // if len of ipv4 hdr is not equal to 20bytes that means that header
      // contains ip options, and we dont support em
      return XDP_DROP;
    }
    pckt->tos = iph->tos;
    *protocol = iph->protocol;
    pckt->flow.proto = *protocol;
    *pkt_bytes = bpf_ntohs(iph->tot_len);
    off += IPV4_HDR_LEN_NO_OPT;

    if (iph->frag_off & PCKT_FRAGMENTED) {
      // we drop fragmented packets.
      return XDP_DROP;
    }
    if (*protocol == IPPROTO_ICMP) {
      action = parse_icmp(data, data_end, off, pckt);
      if (action >= 0) {
        return action;
      }
    } else {
      pckt->flow.src = iph->saddr;
      pckt->flow.dst = iph->daddr;
    }
  }
  return FURTHER_PROCESSING;
}

#ifdef INLINE_DECAP_GENERIC
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
        "opVar": "    __u32* decap_dst_flags ",
        "inpVar": [
          " &decap_dst",
          " &dst_addr"
        ]
      },
      {
        "opVar": "    data_stats ",
        "inpVar": [
          " &stats",
          " &stats_key"
        ]
      }
    ]
  },
  "startLine": 233,
  "endLine": 255,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "check_decap_dst",
  "updateMaps": [],
  "readMaps": [
    "  stats",
    " decap_dst"
  ],
  "input": [
    "struct packet_description *pckt",
    " bool is_ipv6",
    " bool *pass"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int check_decap_dst (struct packet_description *pckt, bool is_ipv6, bool *pass)\n",
    "{\n",
    "    struct address dst_addr = {}\n",
    "    ;\n",
    "    struct lb_stats *data_stats;\n",
    "    if (is_ipv6) {\n",
    "        memcpy (dst_addr.addrv6, pckt->flow.dstv6, 16);\n",
    "    }\n",
    "    else {\n",
    "        dst_addr.addr = pckt->flow.dst;\n",
    "    }\n",
    "    __u32 *decap_dst_flags = bpf_map_lookup_elem (&decap_dst, &dst_addr);\n",
    "    if (decap_dst_flags) {\n",
    "        *pass = false;\n",
    "        __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;\n",
    "        data_stats = bpf_map_lookup_elem (& stats, & stats_key);\n",
    "        if (!data_stats) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        data_stats->v1 += 1;\n",
    "    }\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Given input \"pckt\", check if its flow's dst is legal. if it does, increase the coresponding stats's amount ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int
check_decap_dst(struct packet_description* pckt, bool is_ipv6, bool* pass) {
  struct address dst_addr = {};
  struct lb_stats* data_stats;

  if (is_ipv6) {
    memcpy(dst_addr.addrv6, pckt->flow.dstv6, 16);
  } else {
    dst_addr.addr = pckt->flow.dst;
  }
  __u32* decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_addr);

  if (decap_dst_flags) {
    *pass = false;
    __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (!data_stats) {
      return XDP_DROP;
    }
    data_stats->v1 += 1;
  }
  return FURTHER_PROCESSING;
}

#endif // of INLINE_DECAP_GENERIC

#ifdef GLOBAL_LRU_LOOKUP

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 261,
  "endLine": 277,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "reals_have_same_addr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct real_definition *a",
    " struct real_definition *b"
  ],
  "output": "staticinlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline bool reals_have_same_addr (struct real_definition *a, struct real_definition *b)\n",
    "{\n",
    "    if (a->flags != b->flags) {\n",
    "        return false;\n",
    "    }\n",
    "    if (a->flags & F_IPV6) {\n",
    "        for (int i = 0; i < 4; i++) {\n",
    "            if (a->dstv6[i] != b->dstv6[i]) {\n",
    "                return false;\n",
    "            }\n",
    "            return true;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        return a->dst == b->dst;\n",
    "    }\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Function checks the input 2 backend servers have the same dst addresses ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline bool reals_have_same_addr(
    struct real_definition* a,
    struct real_definition* b) {
  if (a->flags != b->flags) {
    return false;
  }
  if (a->flags & F_IPV6) {
    for (int i = 0; i < 4; i++) {
      if (a->dstv6[i] != b->dstv6[i]) {
        return false;
      }
      return true;
    }
  } else {
    return a->dst == b->dst;
  }
}

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
        "opVar": "    void* g_lru_map ",
        "inpVar": [
          " &global_lru_maps",
          " &cpu_num"
        ]
      },
      {
        "opVar": "  struct lb_stats* global_lru_stats ",
        "inpVar": [
          "      &stats",
          " &global_lru_stats_key"
        ]
      },
      {
        "opVar": "      struct lb_stats* global_lru_mismatch_stats ",
        "inpVar": [
          "          &stats",
          " &global_lru_mismatch_stats_key"
        ]
      }
    ]
  },
  "startLine": 279,
  "endLine": 335,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "perform_global_lru_lookup",
  "updateMaps": [],
  "readMaps": [
    " global_lru_maps",
    " stats"
  ],
  "input": [
    "struct real_definition **dst",
    " struct packet_description *pckt",
    " __u32 cpu_num",
    " struct vip_meta *vip_info",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int perform_global_lru_lookup (struct real_definition **dst, struct packet_description *pckt, __u32 cpu_num, struct vip_meta *vip_info, bool is_ipv6)\n",
    "{\n",
    "    void *g_lru_map = bpf_map_lookup_elem (&global_lru_maps, &cpu_num);\n",
    "    __u32 global_lru_stats_key = MAX_VIPS + GLOBAL_LRU_CNTR;\n",
    "    struct lb_stats *global_lru_stats = bpf_map_lookup_elem (&stats, &global_lru_stats_key);\n",
    "    if (!global_lru_stats) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    if (!g_lru_map) {\n",
    "        global_lru_stats->v1 += 1;\n",
    "        g_lru_map = &fallback_glru;\n",
    "    }\n",
    "    connection_table_lookup (dst, pckt, g_lru_map, true);\n",
    "    if (*dst) {\n",
    "        global_lru_stats->v2 += 1;\n",
    "        struct real_definition *dst_consistent_hash = NULL;\n",
    "        if (get_packet_dst (&dst_consistent_hash, pckt, vip_info, is_ipv6, NULL)) {\n",
    "            __u32 global_lru_mismatch_stats_key = MAX_VIPS + GLOBAL_LRU_MISMATCH_CNTR;\n",
    "            struct lb_stats *global_lru_mismatch_stats = bpf_map_lookup_elem (&stats, &global_lru_mismatch_stats_key);\n",
    "            if (dst_consistent_hash && global_lru_mismatch_stats) {\n",
    "                if (reals_have_same_addr (dst_consistent_hash, *dst)) {\n",
    "                    global_lru_mismatch_stats->v1++;\n",
    "                }\n",
    "                else {\n",
    "                    global_lru_mismatch_stats->v2++;\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return FURTHER_PROCESSING;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " (can't understand) find the lru_map from global cache based on gicen cpu_num, ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int perform_global_lru_lookup(
    struct real_definition** dst,
    struct packet_description* pckt,
    __u32 cpu_num,
    struct vip_meta* vip_info,
    bool is_ipv6) {
  // lookup in the global cache
  void* g_lru_map = bpf_map_lookup_elem(&global_lru_maps, &cpu_num);
  __u32 global_lru_stats_key = MAX_VIPS + GLOBAL_LRU_CNTR;

  struct lb_stats* global_lru_stats =
      bpf_map_lookup_elem(&stats, &global_lru_stats_key);
  if (!global_lru_stats) {
    return XDP_DROP;
  }

  if (!g_lru_map) {
    // We were not able to retrieve the global lru for this cpu.
    // This counter should never be anything except 0 in prod.
    // We are going to use it for monitoring.
    global_lru_stats->v1 += 1; // global lru map doesn't exist for this cpu
    g_lru_map = &fallback_glru;
  }

  connection_table_lookup(dst, pckt, g_lru_map, /*isGlobalLru=*/true);
  if (*dst) {
    global_lru_stats->v2 += 1; // we routed a flow using global lru

    // Find the real that we route the packet to if we use consistent hashing
    struct real_definition* dst_consistent_hash = NULL;
    if (get_packet_dst(
            &dst_consistent_hash,
            pckt,
            vip_info,
            is_ipv6,
            /*lru_map=*/NULL)) {
      __u32 global_lru_mismatch_stats_key = MAX_VIPS + GLOBAL_LRU_MISMATCH_CNTR;

      struct lb_stats* global_lru_mismatch_stats =
          bpf_map_lookup_elem(&stats, &global_lru_mismatch_stats_key);

      if (dst_consistent_hash && global_lru_mismatch_stats) {
        if (reals_have_same_addr(dst_consistent_hash, *dst)) {
          // We route to the same real as that indicated by the consistent
          // hash
          global_lru_mismatch_stats->v1++;
        } else {
          // We route to a real different from that indicated by the
          // consistent hash
          global_lru_mismatch_stats->v2++;
        }
      }
    }
  }

  return FURTHER_PROCESSING;
}

#endif // GLOBAL_LRU_LOOKUP

#ifdef INLINE_DECAP_IPIP
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 340,
  "endLine": 387,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "process_encaped_ipip_pckt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void **data",
    " void **data_end",
    " struct xdp_md *xdp",
    " bool *is_ipv6",
    " __u8 *protocol",
    " bool pass"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int process_encaped_ipip_pckt (void **data, void **data_end, struct xdp_md *xdp, bool *is_ipv6, __u8 *protocol, bool pass)\n",
    "{\n",
    "    int action;\n",
    "    if (*protocol == IPPROTO_IPIP) {\n",
    "        if (*is_ipv6) {\n",
    "            int offset = sizeof (struct ipv6hdr) + sizeof (struct ethhdr);\n",
    "            if ((*data + offset) > *data_end) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            action = decrement_ttl (* data, * data_end, offset, false);\n",
    "            if (!decap_v6 (xdp, data, data_end, true)) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            *is_ipv6 = false;\n",
    "        }\n",
    "        else {\n",
    "            int offset = sizeof (struct iphdr) + sizeof (struct ethhdr);\n",
    "            if ((*data + offset) > *data_end) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            action = decrement_ttl (* data, * data_end, offset, false);\n",
    "            if (!decap_v4 (xdp, data, data_end)) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else if (*protocol == IPPROTO_IPV6) {\n",
    "        int offset = sizeof (struct ipv6hdr) + sizeof (struct ethhdr);\n",
    "        if ((*data + offset) > *data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        action = decrement_ttl (* data, * data_end, offset, true);\n",
    "        if (!decap_v6 (xdp, data, data_end, false)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    if (action >= 0) {\n",
    "        return action;\n",
    "    }\n",
    "    if (pass) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    return recirculate (xdp);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Used for IPIP packets, Based on the encapsulate packet protocol type,  call the appropriate decapsulation function and decrement ttl ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int process_encaped_ipip_pckt(
    void** data,
    void** data_end,
    struct xdp_md* xdp,
    bool* is_ipv6,
    __u8* protocol,
    bool pass) {
  int action;
  if (*protocol == IPPROTO_IPIP) {
    if (*is_ipv6) {
      int offset = sizeof(struct ipv6hdr) + sizeof(struct ethhdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
      *is_ipv6 = false;
    } else {
      int offset = sizeof(struct iphdr) + sizeof(struct ethhdr);
      if ((*data + offset) > *data_end) {
        return XDP_DROP;
      }
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!decap_v4(xdp, data, data_end)) {
        return XDP_DROP;
      }
    }
  } else if (*protocol == IPPROTO_IPV6) {
    int offset = sizeof(struct ipv6hdr) + sizeof(struct ethhdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, true);
    if (!decap_v6(xdp, data, data_end, false)) {
      return XDP_DROP;
    }
  }
  if (action >= 0) {
    return action;
  }
  if (pass) {
    // pass packet to kernel after decapsulation
    return XDP_PASS;
  }
  return recirculate(xdp);
}
#endif // of INLINE_DECAP_IPIP

#ifdef INLINE_DECAP_GUE
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 391,
  "endLine": 441,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "process_encaped_gue_pckt",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void **data",
    " void **data_end",
    " struct xdp_md *xdp",
    " bool is_ipv6",
    " bool pass"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int process_encaped_gue_pckt (void **data, void **data_end, struct xdp_md *xdp, bool is_ipv6, bool pass)\n",
    "{\n",
    "    int offset = 0;\n",
    "    int action;\n",
    "    if (is_ipv6) {\n",
    "        __u8 v6 = 0;\n",
    "        offset = sizeof (struct ipv6hdr) + sizeof (struct ethhdr) + sizeof (struct udphdr);\n",
    "        if ((*data + offset + 1) > *data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        v6 = ((__u8 *) (*data))[offset];\n",
    "        v6 &= GUEV1_IPV6MASK;\n",
    "        if (v6) {\n",
    "            action = decrement_ttl (* data, * data_end, offset, true);\n",
    "            if (!gue_decap_v6 (xdp, data, data_end, false)) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            action = decrement_ttl (* data, * data_end, offset, false);\n",
    "            if (!gue_decap_v6 (xdp, data, data_end, true)) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        offset = sizeof (struct iphdr) + sizeof (struct ethhdr) + sizeof (struct udphdr);\n",
    "        if ((*data + offset) > *data_end) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        action = decrement_ttl (* data, * data_end, offset, false);\n",
    "        if (!gue_decap_v4 (xdp, data, data_end)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    if (action >= 0) {\n",
    "        return action;\n",
    "    }\n",
    "    if (pass) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    return recirculate (xdp);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Used for GUE packets,Based on the encapsulate packet protocol type,  call the appropriate decapsulation function and decrement ttl ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int 
process_encaped_gue_pckt(
    void** data,
    void** data_end,
    struct xdp_md* xdp,
    bool is_ipv6,
    bool pass) {
  int offset = 0;
  int action;
  if (is_ipv6) {
    __u8 v6 = 0;
    offset =
        sizeof(struct ipv6hdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    // 1 byte for gue v1 marker to figure out what is internal protocol
    if ((*data + offset + 1) > *data_end) {
      return XDP_DROP;
    }
    v6 = ((__u8*)(*data))[offset];
    v6 &= GUEV1_IPV6MASK;
    if (v6) {
      // inner packet is ipv6 as well
      action = decrement_ttl(*data, *data_end, offset, true);
      if (!gue_decap_v6(xdp, data, data_end, false)) {
        return XDP_DROP;
      }
    } else {
      // inner packet is ipv4
      action = decrement_ttl(*data, *data_end, offset, false);
      if (!gue_decap_v6(xdp, data, data_end, true)) {
        return XDP_DROP;
      }
    }
  } else {
    offset =
        sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr);
    if ((*data + offset) > *data_end) {
      return XDP_DROP;
    }
    action = decrement_ttl(*data, *data_end, offset, false);
    if (!gue_decap_v4(xdp, data, data_end)) {
      return XDP_DROP;
    }
  }
  if (action >= 0) {
    return action;
  }
  if (pass) {
    return XDP_PASS;
  }
  return recirculate(xdp);
}
#endif // of INLINE_DECAP_GUE

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
        "opVar": "  struct lb_stats* quic_version ",
        "inpVar": [
          "      &stats",
          " &quic_version_stats_key"
        ]
      }
    ]
  },
  "startLine": 444,
  "endLine": 457,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "increment_quic_cid_version_stats",
  "updateMaps": [],
  "readMaps": [
    " stats"
  ],
  "input": [
    "int host_id"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline void increment_quic_cid_version_stats (int host_id)\n",
    "{\n",
    "    __u32 quic_version_stats_key = MAX_VIPS + QUIC_CID_VERSION_STATS;\n",
    "    struct lb_stats *quic_version = bpf_map_lookup_elem (&stats, &quic_version_stats_key);\n",
    "    if (!quic_version) {\n",
    "        return;\n",
    "    }\n",
    "    if (host_id > QUIC_CONNID_VERSION_V1_MAX_VAL) {\n",
    "        quic_version->v2 += 1;\n",
    "    }\n",
    "    else {\n",
    "        quic_version->v1 += 1;\n",
    "    }\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " Function updates quic protocol stats ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline void
increment_quic_cid_version_stats(int host_id) {
  __u32 quic_version_stats_key = MAX_VIPS + QUIC_CID_VERSION_STATS;
  struct lb_stats* quic_version =
      bpf_map_lookup_elem(&stats, &quic_version_stats_key);
  if (!quic_version) {
    return;
  }
  if (host_id > QUIC_CONNID_VERSION_V1_MAX_VAL) {
    quic_version->v2 += 1;
  } else {
    quic_version->v1 += 1;
  }
}

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
        "opVar": "  struct lb_stats* quic_drop ",
        "inpVar": [
          "      &stats",
          " &quic_drop_stats_key"
        ]
      }
    ]
  },
  "startLine": 459,
  "endLine": 468,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "increment_quic_cid_drop_no_real",
  "updateMaps": [],
  "readMaps": [
    " stats"
  ],
  "input": [
    "NA"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline void increment_quic_cid_drop_no_real ()\n",
    "{\n",
    "    __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;\n",
    "    struct lb_stats *quic_drop = bpf_map_lookup_elem (&stats, &quic_drop_stats_key);\n",
    "    if (!quic_drop) {\n",
    "        return;\n",
    "    }\n",
    "    quic_drop->v1 += 1;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " lookup stats by QUIC_CID_DROP_STATS, increment stats v1 by 1 ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline void
increment_quic_cid_drop_no_real() {
  __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;
  struct lb_stats* quic_drop =
      bpf_map_lookup_elem(&stats, &quic_drop_stats_key);
  if (!quic_drop) {
    return;
  }
  quic_drop->v1 += 1;
}

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
        "opVar": "  struct lb_stats* quic_drop ",
        "inpVar": [
          "      &stats",
          " &quic_drop_stats_key"
        ]
      }
    ]
  },
  "startLine": 470,
  "endLine": 478,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "increment_quic_cid_drop_real_0",
  "updateMaps": [],
  "readMaps": [
    " stats"
  ],
  "input": [
    "NA"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline void increment_quic_cid_drop_real_0 ()\n",
    "{\n",
    "    __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;\n",
    "    struct lb_stats *quic_drop = bpf_map_lookup_elem (&stats, &quic_drop_stats_key);\n",
    "    if (!quic_drop) {\n",
    "        return;\n",
    "    }\n",
    "    quic_drop->v2 += 1;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " lookup stats by QUIC_CID_DROP_STATS, update Corresponding stats's v2 ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline void increment_quic_cid_drop_real_0() {
  __u32 quic_drop_stats_key = MAX_VIPS + QUIC_CID_DROP_STATS;
  struct lb_stats* quic_drop =
      bpf_map_lookup_elem(&stats, &quic_drop_stats_key);
  if (!quic_drop) {
    return;
  }
  quic_drop->v2 += 1;
}

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
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with preemption disabled , which means that the SMP processor id is stable during all the execution of the program. ",
          "Return": " The SMP id of the processor running the program.",
          "Function Name": "bpf_get_smp_processor_id",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "  vip_info ",
        "inpVar": [
          " &vip_map",
          " &vip"
        ]
      },
      {
        "opVar": "    vip_info ",
        "inpVar": [
          " &vip_map",
          " &vip"
        ]
      },
      {
        "opVar": "    data_stats ",
        "inpVar": [
          " &stats",
          " &stats_key"
        ]
      },
      {
        "opVar": "  data_stats ",
        "inpVar": [
          " &stats",
          " &stats_key"
        ]
      },
      {
        "opVar": "    struct lb_stats* quic_stats ",
        "inpVar": [
          " &stats",
          " &quic_stats_key"
        ]
      },
      {
        "opVar": "      __u32* real_pos ",
        "inpVar": [
          " &server_id_map",
          " &key"
        ]
      },
      {
        "opVar": "          dst ",
        "inpVar": [
          " &reals",
          " &key"
        ]
      },
      {
        "opVar": "    void* lru_map ",
        "inpVar": [
          " &lru_mapping",
          " &cpu_num"
        ]
      },
      {
        "opVar": "      struct lb_stats* lru_stats ",
        "inpVar": [
          " &stats",
          " &lru_stats_key"
        ]
      },
      {
        "opVar": "      struct lb_stats* routing_stats ",
        "inpVar": [
          "          &stats",
          " &routing_stats_key"
        ]
      },
      {
        "opVar": "        struct lb_stats* lru_stats ",
        "inpVar": [
          "            &stats",
          " &lru_stats_key"
        ]
      },
      {
        "opVar": "        cval ",
        "inpVar": [
          " &ctl_array",
          " &mac_addr_pos"
        ]
      },
      {
        "opVar": "  data_stats ",
        "inpVar": [
          " &stats",
          " &vip_num"
        ]
      },
      {
        "opVar": "    data_stats ",
        "inpVar": [
          " &reals_stats",
          " &pckt.real_index"
        ]
      }
    ],
    "bpf_get_smp_processor_id": [
      {
        "opVar": "        __u32 cpu_num ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 480,
  "endLine": 791,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "process_packet",
  "updateMaps": [],
  "readMaps": [
    " server_id_map",
    "  vip_map",
    "  reals_stats",
    " lru_mapping",
    "  reals",
    "  stats",
    "  ctl_array",
    " stats"
  ],
  "input": [
    "struct xdp_md *xdp",
    " __u64 off",
    " bool is_ipv6"
  ],
  "output": "staticinlineint",
  "helper": [
    "bpf_get_smp_processor_id",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "tracepoint",
    "sk_skb",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline int process_packet (struct xdp_md *xdp, __u64 off, bool is_ipv6)\n",
    "{\n",
    "    void *data = (void *) (long) xdp->data;\n",
    "    void *data_end = (void *) (long) xdp->data_end;\n",
    "    struct ctl_value *cval;\n",
    "    struct real_definition *dst = NULL;\n",
    "    struct packet_description pckt = {}\n",
    "    ;\n",
    "    struct vip_definition vip = {}\n",
    "    ;\n",
    "    struct vip_meta *vip_info;\n",
    "    struct lb_stats *data_stats;\n",
    "    __u64 iph_len;\n",
    "    __u8 protocol;\n",
    "    __u16 original_sport;\n",
    "    int action;\n",
    "    __u32 vip_num;\n",
    "    __u32 mac_addr_pos = 0;\n",
    "    __u16 pkt_bytes;\n",
    "    action = process_l3_headers (& pckt, & protocol, off, & pkt_bytes, data, data_end, is_ipv6);\n",
    "    if (action >= 0) {\n",
    "        return action;\n",
    "    }\n",
    "    protocol = pckt.flow.proto;\n",
    "\n",
    "#ifdef INLINE_DECAP_IPIP\n",
    "    if (protocol == IPPROTO_IPIP) {\n",
    "        bool pass = true;\n",
    "        action = check_decap_dst (& pckt, is_ipv6, & pass);\n",
    "        if (action >= 0) {\n",
    "            return action;\n",
    "        }\n",
    "        return process_encaped_ipip_pckt (&data, &data_end, xdp, &is_ipv6, &protocol, pass);\n",
    "    }\n",
    "    else if (protocol == IPPROTO_IPV6) {\n",
    "        bool pass = true;\n",
    "        action = check_decap_dst (& pckt, is_ipv6, & pass);\n",
    "        if (action >= 0) {\n",
    "            return action;\n",
    "        }\n",
    "        return process_encaped_ipip_pckt (&data, &data_end, xdp, &is_ipv6, &protocol, pass);\n",
    "    }\n",
    "\n",
    "#endif // INLINE_DECAP_IPIP\n",
    "    if (protocol == IPPROTO_TCP) {\n",
    "        if (!parse_tcp (data, data_end, is_ipv6, &pckt)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    else if (protocol == IPPROTO_UDP) {\n",
    "        if (!parse_udp (data, data_end, is_ipv6, &pckt)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "\n",
    "#ifdef INLINE_DECAP_GUE\n",
    "        if (pckt.flow.port16[1] == bpf_htons (GUE_DPORT)) {\n",
    "            bool pass = true;\n",
    "            action = check_decap_dst (& pckt, is_ipv6, & pass);\n",
    "            if (action >= 0) {\n",
    "                return action;\n",
    "            }\n",
    "            return process_encaped_gue_pckt (&data, &data_end, xdp, is_ipv6, pass);\n",
    "        }\n",
    "\n",
    "#endif // of INLINE_DECAP_GUE\n",
    "    }\n",
    "    else {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    if (is_ipv6) {\n",
    "        memcpy (vip.vipv6, pckt.flow.dstv6, 16);\n",
    "    }\n",
    "    else {\n",
    "        vip.vip = pckt.flow.dst;\n",
    "    }\n",
    "    vip.port = pckt.flow.port16[1];\n",
    "    vip.proto = pckt.flow.proto;\n",
    "    vip_info = bpf_map_lookup_elem (& vip_map, & vip);\n",
    "    if (!vip_info) {\n",
    "        vip.port = 0;\n",
    "        vip_info = bpf_map_lookup_elem (& vip_map, & vip);\n",
    "        if (!vip_info) {\n",
    "            return XDP_PASS;\n",
    "        }\n",
    "        if (!(vip_info->flags & F_HASH_DPORT_ONLY)) {\n",
    "            pckt.flow.port16[1] = 0;\n",
    "        }\n",
    "    }\n",
    "    if (data_end - data > MAX_PCKT_SIZE) {\n",
    "        REPORT_PACKET_TOOBIG (xdp, data, data_end - data, false);\n",
    "\n",
    "#ifdef ICMP_TOOBIG_GENERATION\n",
    "        __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;\n",
    "        data_stats = bpf_map_lookup_elem (& stats, & stats_key);\n",
    "        if (!data_stats) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        if (is_ipv6) {\n",
    "            data_stats->v2 += 1;\n",
    "        }\n",
    "        else {\n",
    "            data_stats->v1 += 1;\n",
    "        }\n",
    "        return send_icmp_too_big (xdp, is_ipv6, data_end - data);\n",
    "\n",
    "#else\n",
    "        return XDP_DROP;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    __u32 stats_key = MAX_VIPS + LRU_CNTRS;\n",
    "    data_stats = bpf_map_lookup_elem (& stats, & stats_key);\n",
    "    if (!data_stats) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    data_stats->v1 += 1;\n",
    "    if ((vip_info->flags & F_QUIC_VIP)) {\n",
    "        __u32 quic_stats_key = MAX_VIPS + QUIC_ROUTE_STATS;\n",
    "        struct lb_stats *quic_stats = bpf_map_lookup_elem (&stats, &quic_stats_key);\n",
    "        if (!quic_stats) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        int real_index;\n",
    "        real_index = parse_quic (data, data_end, is_ipv6, & pckt);\n",
    "        if (real_index > 0) {\n",
    "            increment_quic_cid_version_stats (real_index);\n",
    "            __u32 key = real_index;\n",
    "            __u32 *real_pos = bpf_map_lookup_elem (&server_id_map, &key);\n",
    "            if (real_pos) {\n",
    "                key = *real_pos;\n",
    "                if (key == 0) {\n",
    "                    increment_quic_cid_drop_real_0 ();\n",
    "                    quic_stats->v1 += 1;\n",
    "                }\n",
    "                else {\n",
    "                    pckt.real_index = key;\n",
    "                    dst = bpf_map_lookup_elem (& reals, & key);\n",
    "                    if (!dst) {\n",
    "                        increment_quic_cid_drop_no_real ();\n",
    "                        REPORT_QUIC_PACKET_DROP_NO_REAL (xdp, data, data_end - data, false);\n",
    "                        return XDP_DROP;\n",
    "                    }\n",
    "                    quic_stats->v2 += 1;\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                quic_stats->v1 += 1;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            quic_stats->v1 += 1;\n",
    "        }\n",
    "    }\n",
    "    original_sport = pckt.flow.port16[0];\n",
    "    if (!dst) {\n",
    "        if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {\n",
    "            pckt.flow.port16[0] = 0;\n",
    "        }\n",
    "        __u32 cpu_num = bpf_get_smp_processor_id ();\n",
    "        void *lru_map = bpf_map_lookup_elem (&lru_mapping, &cpu_num);\n",
    "        if (!lru_map) {\n",
    "            lru_map = &fallback_cache;\n",
    "            __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;\n",
    "            struct lb_stats *lru_stats = bpf_map_lookup_elem (&stats, &lru_stats_key);\n",
    "            if (!lru_stats) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            lru_stats->v1 += 1;\n",
    "        }\n",
    "\n",
    "#ifdef TCP_SERVER_ID_ROUTING\n",
    "        if (pckt.flow.proto == IPPROTO_TCP && !(pckt.flags & F_SYN_SET)) {\n",
    "            __u32 routing_stats_key = MAX_VIPS + TCP_SERVER_ID_ROUTE_STATS;\n",
    "            struct lb_stats *routing_stats = bpf_map_lookup_elem (&stats, &routing_stats_key);\n",
    "            if (!routing_stats) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            if (tcp_hdr_opt_lookup (xdp, is_ipv6, &dst, &pckt, vip_info->flags & F_LRU_BYPASS, lru_map) == FURTHER_PROCESSING) {\n",
    "                routing_stats->v1 += 1;\n",
    "            }\n",
    "            else {\n",
    "                routing_stats->v2 += 1;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif // TCP_SERVER_ID_ROUTING\n",
    "        if (!dst && !(pckt.flags & F_SYN_SET) && !(vip_info->flags & F_LRU_BYPASS)) {\n",
    "            connection_table_lookup (&dst, &pckt, lru_map, false);\n",
    "        }\n",
    "\n",
    "#ifdef GLOBAL_LRU_LOOKUP\n",
    "        if (!dst && !(pckt.flags & F_SYN_SET) && vip_info->flags & F_GLOBAL_LRU) {\n",
    "            int global_lru_lookup_result = perform_global_lru_lookup (& dst, & pckt, cpu_num, vip_info, is_ipv6);\n",
    "            if (global_lru_lookup_result >= 0) {\n",
    "                return global_lru_lookup_result;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif // GLOBAL_LRU_LOOKUP\n",
    "        if (!dst) {\n",
    "            if (pckt.flow.proto == IPPROTO_TCP) {\n",
    "                __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTR;\n",
    "                struct lb_stats *lru_stats = bpf_map_lookup_elem (&stats, &lru_stats_key);\n",
    "                if (!lru_stats) {\n",
    "                    return XDP_DROP;\n",
    "                }\n",
    "                if (pckt.flags & F_SYN_SET) {\n",
    "                    lru_stats->v1 += 1;\n",
    "                }\n",
    "                else {\n",
    "                    REPORT_TCP_NONSYN_LRUMISS (xdp, data, data_end - data, false);\n",
    "                    lru_stats->v2 += 1;\n",
    "                }\n",
    "            }\n",
    "            if (!get_packet_dst (&dst, &pckt, vip_info, is_ipv6, lru_map)) {\n",
    "                return XDP_DROP;\n",
    "            }\n",
    "            data_stats->v2 += 1;\n",
    "        }\n",
    "    }\n",
    "    cval = bpf_map_lookup_elem (& ctl_array, & mac_addr_pos);\n",
    "    if (!cval) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    vip_num = vip_info->vip_num;\n",
    "    data_stats = bpf_map_lookup_elem (& stats, & vip_num);\n",
    "    if (!data_stats) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    data_stats->v1 += 1;\n",
    "    data_stats->v2 += pkt_bytes;\n",
    "    data_stats = bpf_map_lookup_elem (& reals_stats, & pckt.real_index);\n",
    "    if (!data_stats) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    data_stats->v1 += 1;\n",
    "    data_stats->v2 += pkt_bytes;\n",
    "\n",
    "#ifdef LOCAL_DELIVERY_OPTIMIZATION\n",
    "    if ((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    pckt.flow.port16[0] = original_sport;\n",
    "    if (dst->flags & F_IPV6) {\n",
    "        if (!PCKT_ENCAP_V6(xdp, cval, is_ipv6, &pckt, dst, pkt_bytes)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if (!PCKT_ENCAP_V4(xdp, cval, &pckt, dst, pkt_bytes)) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "    }\n",
    "    return XDP_TX;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " This function process the packet based on the protocol and updates corresponding stats. ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline int process_packet(struct xdp_md* xdp, __u64 off, bool is_ipv6) {
  void* data = (void*)(long)xdp->data;
  void* data_end = (void*)(long)xdp->data_end;
  struct ctl_value* cval;
  struct real_definition* dst = NULL;
  struct packet_description pckt = {};
  struct vip_definition vip = {};
  struct vip_meta* vip_info;
  struct lb_stats* data_stats;
  __u64 iph_len;
  __u8 protocol;
  __u16 original_sport;

  int action;
  __u32 vip_num;
  __u32 mac_addr_pos = 0;
  __u16 pkt_bytes;
  action = process_l3_headers(
      &pckt, &protocol, off, &pkt_bytes, data, data_end, is_ipv6);
  if (action >= 0) {
    return action;
  }
  protocol = pckt.flow.proto;

#ifdef INLINE_DECAP_IPIP
  /* This is to workaround a verifier issue for 5.2.
   * The reason is that 5.2 verifier does not handle register
   * copy states properly while 5.6 handles properly.
   *
   * For the following source code:
   *   if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
   *     ...
   *   }
   * llvm12 may generate the following simplified code sequence
   *   100  r5 = *(u8 *)(r9 +51)  // r5 is the protocol
   *   120  r4 = r5
   *   121  if r4 s> 0x10 goto target1
   *   122  *(u64 *)(r10 -184) = r5
   *   123  if r4 == 0x4 goto target2
   *   ...
   *   target2:
   *   150  r1 = *(u64 *)(r10 -184)
   *   151  if (r1 != 4) { __unreachable__}
   *
   * For the path 123->150->151, 5.6 correctly noticed
   * at insn 150: r4, r5, *(u64 *)(r10 -184) all have value 4.
   * while 5.2 has *(u64 *)(r10 -184) holding "r5" which could be
   * any value 0-255. In 5.2, "__unreachable" code is verified
   * and it caused verifier failure.
   */
  if (protocol == IPPROTO_IPIP) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if (action >= 0) {
      return action;
    }
    return process_encaped_ipip_pckt(
        &data, &data_end, xdp, &is_ipv6, &protocol, pass);
  } else if (protocol == IPPROTO_IPV6) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if (action >= 0) {
      return action;
    }
    return process_encaped_ipip_pckt(
        &data, &data_end, xdp, &is_ipv6, &protocol, pass);
  }
#endif // INLINE_DECAP_IPIP

  if (protocol == IPPROTO_TCP) {
    if (!parse_tcp(data, data_end, is_ipv6, &pckt)) {
      return XDP_DROP;
    }
  } else if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, is_ipv6, &pckt)) {
      return XDP_DROP;
    }
#ifdef INLINE_DECAP_GUE
    if (pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) {
      bool pass = true;
      action = check_decap_dst(&pckt, is_ipv6, &pass);
      if (action >= 0) {
        return action;
      }
      return process_encaped_gue_pckt(&data, &data_end, xdp, is_ipv6, pass);
    }
#endif // of INLINE_DECAP_GUE
  } else {
    // send to tcp/ip stack
    return XDP_PASS;
  }

  if (is_ipv6) {
    memcpy(vip.vipv6, pckt.flow.dstv6, 16);
  } else {
    vip.vip = pckt.flow.dst;
  }

  vip.port = pckt.flow.port16[1];
  vip.proto = pckt.flow.proto;
  vip_info = bpf_map_lookup_elem(&vip_map, &vip);
  if (!vip_info) {
    vip.port = 0;
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if (!vip_info) {
      return XDP_PASS;
    }

    if (!(vip_info->flags & F_HASH_DPORT_ONLY)) {
      // VIP, which doesnt care about dst port (all packets to this VIP w/ diff
      // dst port but from the same src port/ip must go to the same real
      pckt.flow.port16[1] = 0;
    }
  }

  if (data_end - data > MAX_PCKT_SIZE) {
    REPORT_PACKET_TOOBIG(xdp, data, data_end - data, false);
#ifdef ICMP_TOOBIG_GENERATION
    __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (!data_stats) {
      return XDP_DROP;
    }
    if (is_ipv6) {
      data_stats->v2 += 1;
    } else {
      data_stats->v1 += 1;
    }
    return send_icmp_too_big(xdp, is_ipv6, data_end - data);
#else
    return XDP_DROP;
#endif
  }

  __u32 stats_key = MAX_VIPS + LRU_CNTRS;
  data_stats = bpf_map_lookup_elem(&stats, &stats_key);
  if (!data_stats) {
    return XDP_DROP;
  }

  // total packets
  data_stats->v1 += 1;

  // Lookup dst based on id in packet
  if ((vip_info->flags & F_QUIC_VIP)) {
    __u32 quic_stats_key = MAX_VIPS + QUIC_ROUTE_STATS;
    struct lb_stats* quic_stats = bpf_map_lookup_elem(&stats, &quic_stats_key);
    if (!quic_stats) {
      return XDP_DROP;
    }
    int real_index;
    real_index = parse_quic(data, data_end, is_ipv6, &pckt);
    if (real_index > 0) {
      increment_quic_cid_version_stats(real_index);
      __u32 key = real_index;
      __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
      if (real_pos) {
        key = *real_pos;
        if (key == 0) {
          increment_quic_cid_drop_real_0();
          // increment counter for the CH based routing
          quic_stats->v1 += 1;
        } else {
          pckt.real_index = key;
          dst = bpf_map_lookup_elem(&reals, &key);
          if (!dst) {
            increment_quic_cid_drop_no_real();
            REPORT_QUIC_PACKET_DROP_NO_REAL(xdp, data, data_end - data, false);
            return XDP_DROP;
          }
          quic_stats->v2 += 1;
        }
      } else {
        // increment counter for the CH based routing
        quic_stats->v1 += 1;
      }
    } else {
      quic_stats->v1 += 1;
    }
  }

  // save the original sport before making real selection, possibly changing its
  // value.
  original_sport = pckt.flow.port16[0];

  if (!dst) {
    if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {
      // service, where diff src port, but same ip must go to the same real,
      // e.g. gfs
      pckt.flow.port16[0] = 0;
    }
    __u32 cpu_num = bpf_get_smp_processor_id();
    void* lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
    if (!lru_map) {
      lru_map = &fallback_cache;
      __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;
      struct lb_stats* lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
      if (!lru_stats) {
        return XDP_DROP;
      }
      // We were not able to retrieve per cpu/core lru and falling back to
      // default one. This counter should never be anything except 0 in prod.
      // We are going to use it for monitoring.
      lru_stats->v1 += 1;
    }
#ifdef TCP_SERVER_ID_ROUTING
    // First try to lookup dst in the tcp_hdr_opt (if enabled)
    if (pckt.flow.proto == IPPROTO_TCP && !(pckt.flags & F_SYN_SET)) {
      __u32 routing_stats_key = MAX_VIPS + TCP_SERVER_ID_ROUTE_STATS;
      struct lb_stats* routing_stats =
          bpf_map_lookup_elem(&stats, &routing_stats_key);
      if (!routing_stats) {
        return XDP_DROP;
      }
      if (tcp_hdr_opt_lookup(
              xdp,
              is_ipv6,
              &dst,
              &pckt,
              vip_info->flags & F_LRU_BYPASS,
              lru_map) == FURTHER_PROCESSING) {
        routing_stats->v1 += 1;
      } else {
        routing_stats->v2 += 1;
      }
    }
#endif // TCP_SERVER_ID_ROUTING

    // Next, try to lookup dst in the lru_cache
    if (!dst && !(pckt.flags & F_SYN_SET) &&
        !(vip_info->flags & F_LRU_BYPASS)) {
      connection_table_lookup(&dst, &pckt, lru_map, /*isGlobalLru=*/false);
    }

#ifdef GLOBAL_LRU_LOOKUP
    if (!dst && !(pckt.flags & F_SYN_SET) && vip_info->flags & F_GLOBAL_LRU) {
      int global_lru_lookup_result =
          perform_global_lru_lookup(&dst, &pckt, cpu_num, vip_info, is_ipv6);
      if (global_lru_lookup_result >= 0) {
        return global_lru_lookup_result;
      }
    }
#endif // GLOBAL_LRU_LOOKUP

    // if dst is not found, route via consistent-hashing of the flow.
    if (!dst) {
      if (pckt.flow.proto == IPPROTO_TCP) {
        __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTR;
        struct lb_stats* lru_stats =
            bpf_map_lookup_elem(&stats, &lru_stats_key);
        if (!lru_stats) {
          return XDP_DROP;
        }
        if (pckt.flags & F_SYN_SET) {
          // miss because of new tcp session
          lru_stats->v1 += 1;
        } else {
          // miss of non-syn tcp packet. could be either because of LRU trashing
          // or because another katran is restarting and all the sessions
          // have been reshuffled
          REPORT_TCP_NONSYN_LRUMISS(xdp, data, data_end - data, false);
          lru_stats->v2 += 1;
        }
      }
      if (!get_packet_dst(&dst, &pckt, vip_info, is_ipv6, lru_map)) {
        return XDP_DROP;
      }
      // lru misses (either new connection or lru is full and starts to trash)
      data_stats->v2 += 1;
    }
  }

  cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);

  if (!cval) {
    return XDP_DROP;
  }

  vip_num = vip_info->vip_num;
  data_stats = bpf_map_lookup_elem(&stats, &vip_num);
  if (!data_stats) {
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  // per real statistics
  data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
  if (!data_stats) {
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;
#ifdef LOCAL_DELIVERY_OPTIMIZATION
  if ((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {
    return XDP_PASS;
  }
#endif
  // restore the original sport value to use it as a seed for the GUE sport
  pckt.flow.port16[0] = original_sport;
  if (dst->flags & F_IPV6) {
    if (!PCKT_ENCAP_V6(xdp, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
      return XDP_DROP;
    }
  } else {
    if (!PCKT_ENCAP_V4(xdp, cval, &pckt, dst, pkt_bytes)) {
      return XDP_DROP;
    }
  }

  return XDP_TX;
}

SEC("xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 794,
  "endLine": 817,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "balancer_ingress",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "int balancer_ingress (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    struct ethhdr *eth = data;\n",
    "    __u32 eth_proto;\n",
    "    __u32 nh_off;\n",
    "    nh_off = sizeof (struct ethhdr);\n",
    "    if (data + nh_off > data_end) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    eth_proto = eth->h_proto;\n",
    "    if (eth_proto == BE_ETH_P_IP) {\n",
    "        return process_packet (ctx, nh_off, false);\n",
    "    }\n",
    "    else if (eth_proto == BE_ETH_P_IPV6) {\n",
    "        return process_packet (ctx, nh_off, true);\n",
    "    }\n",
    "    else {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " process the input ctx packet ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
int balancer_ingress(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct ethhdr);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return XDP_DROP;
  }

  eth_proto = eth->h_proto;

  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(ctx, nh_off, false);
  } else if (eth_proto == BE_ETH_P_IPV6) {
    return process_packet(ctx, nh_off, true);
  } else {
    // pass to tcp/ip stack
    return XDP_PASS;
  }
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 818,
  "endLine": 827,
  "File": "/home/palani/github/opened_extraction/examples/katran/balancer_kern.c",
  "funcName": "get_packet_hash",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct packet_description *pckt",
    " bool hash_16bytes"
  ],
  "output": "staticinline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "sched_cls",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint",
    "lwt_seg6local",
    "sk_skb",
    "tracepoint",
    "sock_ops",
    "xdp",
    "sched_act",
    "flow_dissector",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_out",
    "lwt_in"
  ],
  "source": [
    "static inline __u32 get_packet_hash (struct packet_description *pckt, bool hash_16bytes)\n",
    "{\n",
    "    if (hash_16bytes) {\n",
    "        return jhash_2words (jhash (pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6), pckt->flow.ports, INIT_JHASH_SEED);\n",
    "    }\n",
    "    else {\n",
    "        return jhash_2words (pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);\n",
    "    }\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": " return the hash value of input packet ",
      "author": "Nengneng Yu",
      "authorEmail": "ynn1999@bu.edu",
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
__attribute__((__always_inline__)) static inline __u32 get_packet_hash(struct packet_description* pckt,bool hash_16bytes) {
  if (hash_16bytes) {
    return jhash_2words(
        jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
        pckt->flow.ports,
        INIT_JHASH_SEED);
  } else {
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
  }
}


char _license[] SEC("license") = "GPL";
