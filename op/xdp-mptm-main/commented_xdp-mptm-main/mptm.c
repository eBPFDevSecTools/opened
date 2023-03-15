/* SPDX-License-Identifier: GPL-2.0 
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <common/parsing_helpers.h>

#include <kernel/lib/pkt-parse.h>
#include <kernel/lib/pkt-encap.h>
#include <kernel/lib/geneve.h>
#include <kernel/lib/map-defs.h>

/* Defines xdp_stats_map */
#include <common/xdp_stats_kern_user.h>
#include <common/xdp_stats_kern.h>

/* Inspired from Katran.
 * ETH_P_IP and ETH_P_IPV6 in Big Endian format.
 * So we don't have to do htons on each packet
 */
#define BE_ETH_P_IP   0x0008
#define BE_ETH_P_IPV6 0xDD88
#define BE_ETH_P_ARP  0x0608

#define MAX_ENTRIES 1024

struct bpf_map_def SEC("maps") mptm_tnl_info_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(tunnel_map_key_t),
    .value_size  = sizeof(mptm_tunnel_info),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") mptm_tnl_redirect_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES*2,
};

SEC("mptm_encap_xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
    }
  ],
  "helperCallParams": {},
  "startLine": 52,
  "endLine": 99,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm.c",
  "funcName": "mptm_encap",
  "updateMaps": [],
  "readMaps": [
    "  mptm_tnl_info_map"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "XDP_PASS",
    "bpf_redirect_map",
    "bpf_redirect",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int mptm_encap (struct xdp_md *ctx)\n",
    "{\n",
    "    int action = XDP_PASS;\n",
    "    struct ethhdr *eth;\n",
    "    struct iphdr *ip;\n",
    "    struct tunnel_info *tn;\n",
    "    tunnel_map_key_t key;\n",
    "    __u8 tun_type;\n",
    "    void *data = (void *) ((long) ctx->data);\n",
    "    void *data_end = (void *) ((long) ctx->data_end);\n",
    "    if (parse_pkt_headers (data, data_end, &eth, &ip, NULL) != 0) {\n",
    "        goto out;\n",
    "    }\n",
    "    key.s_addr = ip->saddr;\n",
    "    key.d_addr = ip->daddr;\n",
    "    tn = bpf_map_lookup_elem (& mptm_tnl_info_map, & key);\n",
    "    if (tn == NULL) {\n",
    "        mptm_print (\"[ERR] map entry missing for key-{saddr:%x,daddr:%x}\\n\", key.s_addr, key.d_addr);\n",
    "        goto out;\n",
    "    }\n",
    "    tun_type = tn->tunnel_type;\n",
    "    if (tun_type == VLAN) {\n",
    "        action = encap_vlan (ctx, eth, tn);\n",
    "    }\n",
    "    else if (tun_type == GENEVE) {\n",
    "        action = encap_geneve (ctx, eth, tn);\n",
    "    }\n",
    "    else {\n",
    "        bpf_debug (\"[ERR] tunnel type is unknown\");\n",
    "        goto out;\n",
    "    }\n",
    "    if (likely (tn->redirect)) {\n",
    "        __u64 flags = 0;\n",
    "        action = bpf_redirect_map (& mptm_tnl_redirect_devmap, tn -> veth_iface, flags);\n",
    "    }\n",
    "out :\n",
    "    return xdp_stats_record_action (ctx, action);\n",
    "}\n"
  ],
  "called_function_list": [
    "encap_vlan",
    "bpf_debug",
    "parse_pkt_headers",
    "encap_geneve",
    "xdp_stats_record_action",
    "mptm_print",
    "likely"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
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
int mptm_encap(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action

    /* header pointers */
    struct ethhdr *eth;
    struct iphdr *ip;

    /* map values and tunnel informations */
    struct tunnel_info* tn;
    tunnel_map_key_t key;
    __u8 tun_type;

    void *data = (void *)((long)ctx->data);
    void *data_end = (void *)((long)ctx->data_end);

    if (parse_pkt_headers(data, data_end, &eth, &ip, NULL) != 0) {
        goto out;
    }

    key.s_addr = ip->saddr;
    key.d_addr = ip->daddr;

    tn = bpf_map_lookup_elem(&mptm_tnl_info_map, &key);
    if(tn == NULL) {
      mptm_print("[ERR] map entry missing for key-{saddr:%x,daddr:%x}\n",
                 key.s_addr, key.d_addr);
      goto out;
    }

    tun_type = tn->tunnel_type;
    if (tun_type == VLAN) {
        action = encap_vlan(ctx, eth, tn);
    }
    else if (tun_type == GENEVE) {
        action = encap_geneve(ctx, eth, tn);
    } else {
        bpf_debug("[ERR] tunnel type is unknown");
        goto out;
    }

    if (likely(tn->redirect)) {
        __u64 flags = 0; // keep redirect flags zero for now
        action = bpf_redirect_map(&mptm_tnl_redirect_devmap, tn->veth_iface, flags);
    }

  out:
    return xdp_stats_record_action(ctx, action);
}

SEC("mptm_decap_xdp")
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
    },
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ],
          "compatible_hookpoints": [
            "xdp"
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
    }
  ],
  "helperCallParams": {},
  "startLine": 102,
  "endLine": 167,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm.c",
  "funcName": "mptm_decap",
  "updateMaps": [],
  "readMaps": [
    "  mptm_tnl_info_map"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_redirect",
    "XDP_DROP",
    "XDP_PASS",
    "bpf_redirect_map",
    "bpf_xdp_adjust_head",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int mptm_decap (struct xdp_md *ctx)\n",
    "{\n",
    "    int action = XDP_PASS;\n",
    "    struct ethhdr *eth;\n",
    "    struct iphdr *ip;\n",
    "    struct udphdr *udp;\n",
    "    void *data = (void *) ((long) ctx->data);\n",
    "    void *data_end = (void *) ((long) ctx->data_end);\n",
    "    if (parse_pkt_headers (data, data_end, &eth, &ip, &udp) != 0)\n",
    "        goto out;\n",
    "    if (udp->dest == BE_GENEVE_DSTPORT) {\n",
    "        int outer_hdr_size = sizeof (struct genevehdr) + sizeof (struct udphdr) + sizeof (struct iphdr) + sizeof (struct ethhdr);\n",
    "        long ret = bpf_xdp_adjust_head (ctx, outer_hdr_size);\n",
    "        if (ret != 0l) {\n",
    "            mptm_print (\"[Agent:] DROP (BUG): Failure adjusting packet header!\\n\");\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        data = (void *) (long) ctx->data;\n",
    "        data_end = (void *) (long) ctx->data_end;\n",
    "        struct ethhdr *inner_eth;\n",
    "        struct iphdr *inner_ip;\n",
    "        if (parse_pkt_headers (data, data_end, &inner_eth, &inner_ip, NULL) != 0)\n",
    "            goto out;\n",
    "        tunnel_map_key_t key;\n",
    "        struct tunnel_info *tn;\n",
    "        __u8 tun_type;\n",
    "        __u64 flags = 0;\n",
    "        key.s_addr = inner_ip->daddr;\n",
    "        key.d_addr = inner_ip->saddr;\n",
    "        tn = bpf_map_lookup_elem (& mptm_tnl_info_map, & key);\n",
    "        if (tn == NULL) {\n",
    "            mptm_print (\"[ERR] map entry missing for key {saddr:%x,daddr:%x}\\n\", key.s_addr, key.d_addr);\n",
    "            goto out;\n",
    "        }\n",
    "        tun_type = tn->tunnel_type;\n",
    "        if (unlikely (tun_type != GENEVE)) {\n",
    "            mptm_print (\"Packet is changed but did not belong to us!\");\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        action = bpf_redirect_map (& mptm_tnl_redirect_devmap, tn -> eth0_iface, flags);\n",
    "    }\n",
    "out :\n",
    "    return xdp_stats_record_action (ctx, action);\n",
    "}\n"
  ],
  "called_function_list": [
    "parse_pkt_headers",
    "unlikely",
    "mptm_print",
    "xdp_stats_record_action"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
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
int mptm_decap(struct xdp_md *ctx) {
    int action = XDP_PASS;  //default action

    /* header pointers */
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    void *data = (void *)((long)ctx->data);
    void *data_end = (void *)((long)ctx->data_end);

    if (parse_pkt_headers(data, data_end, &eth, &ip, &udp) != 0)
        goto out;

    if (udp->dest == BE_GENEVE_DSTPORT) { // GENEVE packet
        // Check inner packet if there is a rule corresponding to
        // inner source which will be source for us as we received the packet
        int outer_hdr_size = sizeof(struct genevehdr) +
                             sizeof(struct udphdr) +
                             sizeof(struct iphdr) +
                             sizeof(struct ethhdr);
        long ret = bpf_xdp_adjust_head(ctx, outer_hdr_size);
        if (ret != 0l) {
            mptm_print("[Agent:] DROP (BUG): Failure adjusting packet header!\n");
            return XDP_DROP;
        }

        /* recalculate the data pointers */
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        /* header pointers */
        struct ethhdr *inner_eth;
        struct iphdr *inner_ip;

        if (parse_pkt_headers(data, data_end, &inner_eth, &inner_ip, NULL) != 0)
            goto out;

        /* map values and tunnel informations */
        tunnel_map_key_t key;
        struct tunnel_info* tn;
        __u8 tun_type;
        __u64 flags = 0; // keep redirect flags zero for now

        /* Packet is coming from outside so source and dest must be inversed */
        key.s_addr = inner_ip->daddr;
        key.d_addr = inner_ip->saddr;

        tn = bpf_map_lookup_elem(&mptm_tnl_info_map, &key);
        if(tn == NULL) {
            mptm_print("[ERR] map entry missing for key {saddr:%x,daddr:%x}\n", key.s_addr, key.d_addr);
            goto out;
        }

        tun_type = tn->tunnel_type;
        if (unlikely(tun_type != GENEVE)) {
            mptm_print("Packet is changed but did not belong to us!");
            return XDP_DROP;
        }

        action = bpf_redirect_map(&mptm_tnl_redirect_devmap, tn->eth0_iface, flags);
    }

  out:
    return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";

