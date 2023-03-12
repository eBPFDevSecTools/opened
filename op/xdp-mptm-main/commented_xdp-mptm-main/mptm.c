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
        "opVar": "    tn ",
        "inpVar": [
          " &mptm_tnl_info_map",
          " &key"
        ]
      }
    ],
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "        if likelytn-> "
        ]
      }
    ],
    "bpf_redirect": [
      {
        "opVar": "         action ",
        "inpVar": [
          " _map&mptm_tnl_redirect_devmap",
          " tn->veth_iface",
          " flags"
        ]
      }
    ]
  },
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
    "bpf_map_lookup_elem",
    "bpf_redirect",
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "This function performs the encapsulation of specific tunnel on an outgoing packet. It parse the packet eth and ip header using the parse_pkt_headers helper function. It then performs a map lookup into mptm_tnl_info_map with key which is a struct containing the ip source and dst addr of the packet. The map lookup returns a tunnel_info object *tn, which is used further to encapsulate differnet tunnel based on the rule programmed in the tunnel_info object retrieved from the map. This function will then call appropriate helper function encap_<tunnel> to encapsulate appropriate tunnel on the packet and finally redirects the packet to an outbound interface which is pre programmed in a devmap with the key taken as tn->veth_iface object and flags as none. It will return XDP_REDIRECT on successful encapsulation or XDP_PASS/XDP_ABORTED based on the return value of helper functions used.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
    },
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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_xdp_adjust_head": [
      {
        "opVar": "        long ret ",
        "inpVar": [
          " ctx",
          " outer_hdr_size"
        ]
      }
    ],
    "bpf_map_lookup_elem": [
      {
        "opVar": "        tn ",
        "inpVar": [
          " &mptm_tnl_info_map",
          " &key"
        ]
      }
    ],
    "bpf_redirect": [
      {
        "opVar": "                action ",
        "inpVar": [
          " _map&mptm_tnl_redirect_devmap",
          " tn->eth0_iface",
          " flags"
        ]
      }
    ]
  },
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
    "bpf_map_lookup_elem",
    "bpf_xdp_adjust_head",
    "bpf_redirect"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "humanFuncDescription": [
    {
      "description": "This function performs the decapsulation of specific tunnel on an incoming packet. It parse the packet eth, ip and udp header using the parse_pkt_headers helper function. If the packet is a UDP packet and if the UDP dest port is 0xc117 the geneve tunnel destination port, then it will remove the geneve header from the packet,by reducing its data size by sizeof(struct genevehdr+ struct udphdr + struct iphdr + struct ethhdr) by calling bpf_xdp_adjust_head. After that it recalculates the packet headers using parse_pkt_headers and does a sanity check on if Geneve tunnel is what was intended for this packet. Finally the packet is redirected to appropriate interface using mptm_tnl_redirect_devmap",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
    },
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

