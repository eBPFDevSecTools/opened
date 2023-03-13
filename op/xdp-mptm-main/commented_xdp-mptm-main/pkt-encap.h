/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause)
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#ifndef __PKT_ENCAP_H__
#define __PKT_ENCAP_H__

#pragma once

/*
 * The functions are marked as __always_inline, and
 * fully defined in this header file to be included in the BPF program.
 */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include <common/rewrite_helpers.h>

#include <kernel/lib/compiler.h>
#include <kernel/lib/map-defs.h>
#include <kernel/lib/geneve.h>
#include <kernel/lib/mptm-debug.h>

#define DEFAULT_TTL        64
#define BE_GENEVE_DSTPORT  0xc117

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 38,
  "endLine": 46,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "set_dst_mac",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " unsigned char *dst_mac"
  ],
  "output": "static__ALWAYS_INLINE__void",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "cgroup_skb",
    "sched_cls",
    "sk_skb",
    "tracepoint",
    "kprobe",
    "cgroup_sock",
    "cgroup_sysctl",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "xdp",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "lwt_seg6local",
    "sock_ops",
    "lwt_xmit",
    "sched_act"
  ],
  "source": [
    "static __ALWAYS_INLINE__ void set_dst_mac (void *data, unsigned char *dst_mac)\n",
    "{\n",
    "    unsigned short *p = data;\n",
    "    unsigned short *dst = (unsigned short *) dst_mac;\n",
    "    p[0] = dst[0];\n",
    "    p[1] = dst[1];\n",
    "    p[2] = dst[2];\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __ALWAYS_INLINE__ void set_dst_mac(void *data, unsigned char *dst_mac)
{
    unsigned short *p = data;
    unsigned short *dst = (unsigned short *)dst_mac;

    p[0] = dst[0];
    p[1] = dst[1];
    p[2] = dst[2];
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 48,
  "endLine": 56,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "set_src_mac",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data",
    " unsigned char *src_mac"
  ],
  "output": "static__ALWAYS_INLINE__void",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "cgroup_skb",
    "sched_cls",
    "sk_skb",
    "tracepoint",
    "kprobe",
    "cgroup_sock",
    "cgroup_sysctl",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "xdp",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "lwt_seg6local",
    "sock_ops",
    "lwt_xmit",
    "sched_act"
  ],
  "source": [
    "static __ALWAYS_INLINE__ void set_src_mac (void *data, unsigned char *src_mac)\n",
    "{\n",
    "    unsigned short *p = data;\n",
    "    unsigned short *src = (unsigned short *) src_mac;\n",
    "    p[3] = src[0];\n",
    "    p[4] = src[1];\n",
    "    p[5] = src[2];\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __ALWAYS_INLINE__ void set_src_mac(void *data, unsigned char *src_mac)
{
    unsigned short *p = data;
    unsigned short *src = (unsigned short *)src_mac;

    p[3] = src[0];
    p[4] = src[1];
    p[5] = src[2];
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 58,
  "endLine": 67,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "csum_fold_helper",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u64 csum"
  ],
  "output": "static__ALWAYS_INLINE____u16",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "cgroup_skb",
    "sched_cls",
    "sk_skb",
    "tracepoint",
    "kprobe",
    "cgroup_sock",
    "cgroup_sysctl",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "xdp",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "lwt_seg6local",
    "sock_ops",
    "lwt_xmit",
    "sched_act"
  ],
  "source": [
    "static __ALWAYS_INLINE__ __u16 csum_fold_helper (__u64 csum)\n",
    "{\n",
    "    int i;\n",
    "\n",
    "#pragma unroll\n",
    "    for (i = 0; i < 4; i++) {\n",
    "        if (csum >> 16)\n",
    "            csum = (csum & 0xffff) + (csum >> 16);\n",
    "    }\n",
    "    return ~csum;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __ALWAYS_INLINE__ __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 77,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "ipv4_csum_inline",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *iph",
    " __u64 *csum"
  ],
  "output": "static__ALWAYS_INLINE__void",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "cgroup_skb",
    "sched_cls",
    "sk_skb",
    "tracepoint",
    "kprobe",
    "cgroup_sock",
    "cgroup_sysctl",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "xdp",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "lwt_seg6local",
    "sock_ops",
    "lwt_xmit",
    "sched_act"
  ],
  "source": [
    "static __ALWAYS_INLINE__ void ipv4_csum_inline (void *iph, __u64 *csum)\n",
    "{\n",
    "    __u16 *next_iph_u16 = (__u16 *) iph;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (int i = 0; i < sizeof (struct iphdr) >> 1; i++) {\n",
    "        *csum += *next_iph_u16++;\n",
    "    }\n",
    "    *csum = csum_fold_helper (*csum);\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_fold_helper",
    "unroll"
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
static __ALWAYS_INLINE__ void ipv4_csum_inline(void *iph, __u64 *csum)
{
    __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
    for (int i = 0; i<sizeof(struct iphdr)>> 1; i++) {
        *csum += *next_iph_u16++;
    }
    *csum = csum_fold_helper(*csum);
}

/* Pushes a new GENEVE header after the Ethernet header.
 *  Returns 0 on success, -1 on failure.
 */
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
          "Function Name": "XDP_ABORTED",
          "Return": 0,
          "Description": "which serves denoting an exception like state from the program and has the same behavior as XDP_DROP only that XDP_ABORTED passes the trace_xdp_exception tracepoint which can be additionally monitored to detect misbehavior.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        },
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
    }
  ],
  "helperCallParams": {},
  "startLine": 82,
  "endLine": 192,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "__encap_geneve",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " struct ethhdr *eth",
    " geneve_tunnel_info *tn"
  ],
  "output": "static__ALWAYS_INLINE__int",
  "helper": [
    "XDP_ABORTED",
    "bpf_xdp_adjust_head",
    "XDP_PASS",
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __ALWAYS_INLINE__ int __encap_geneve (struct xdp_md *ctx, struct ethhdr *eth, geneve_tunnel_info *tn)\n",
    "{\n",
    "    int gnv_hdr_size = sizeof (struct genevehdr);\n",
    "    int udp_hdr_size = sizeof (struct udphdr);\n",
    "    int ip_hdr_size = sizeof (struct iphdr);\n",
    "    int eth_hdr_size = sizeof (struct ethhdr);\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    int old_size = (int) (data_end - data);\n",
    "    struct ethhdr *eth_inner_hdr = (struct ethhdr *) data;\n",
    "    if (eth_inner_hdr + 1 > data_end) {\n",
    "        mptm_print (\"[Agent: ] ABORTED: Bad ETH header offset \\n\");\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    set_dst_mac (data, tn->inner_dest_mac);\n",
    "    int outer_hdr_size = gnv_hdr_size + udp_hdr_size + ip_hdr_size + eth_hdr_size;\n",
    "    long ret = bpf_xdp_adjust_head (ctx, (0 - outer_hdr_size));\n",
    "    if (ret != 0l) {\n",
    "        mptm_print (\"[Agent:] DROP (BUG): Failure adjusting packet header!\\n\");\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    data = (void *) (long) ctx->data;\n",
    "    data_end = (void *) (long) ctx->data_end;\n",
    "    struct ethhdr *ethcpy;\n",
    "    ethcpy = data;\n",
    "    if (ethcpy + 1 > data_end) {\n",
    "        mptm_print (\"[Agent: ] ABORTED: Bad ETH header offset \\n\");\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    struct iphdr *ip = (struct iphdr *) (ethcpy + 1);\n",
    "    if (ip + 1 > data_end) {\n",
    "        mptm_print (\"ABORTED: Bad ip header offset ip: %x data_end:%x \\n\", ip + 1, data_end);\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    struct udphdr *udp = (struct udphdr *) (ip + 1);\n",
    "    if (udp + 1 > data_end) {\n",
    "        mptm_print (\"ABORTED: Bad udp header offset \\n\");\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    struct genevehdr *geneve = (struct genevehdr *) (udp + 1);\n",
    "    if (geneve + 1 > data_end) {\n",
    "        mptm_print (\"ABORTED: Bad GENEVE header offset \\n\");\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    ethcpy->h_proto = BE_ETH_P_IP;\n",
    "    set_dst_mac (data, tn->dest_mac);\n",
    "    set_src_mac (data, tn->source_mac);\n",
    "    int outer_ip_payload = gnv_hdr_size + udp_hdr_size + ip_hdr_size + old_size;\n",
    "    int outer_udp_payload = gnv_hdr_size + udp_hdr_size + old_size;\n",
    "    ip->version = 4;\n",
    "    ip->ihl = ip_hdr_size >> 2;\n",
    "    ip->frag_off = 0;\n",
    "    ip->protocol = IPPROTO_UDP;\n",
    "    ip->check = 0;\n",
    "    ip->tos = 0;\n",
    "    ip->tot_len = bpf_htons (outer_ip_payload);\n",
    "    ip->daddr = tn->dest_addr;\n",
    "    ip->saddr = tn->source_addr;\n",
    "    ip->ttl = DEFAULT_TTL;\n",
    "    __u64 c_sum = 0;\n",
    "    ipv4_csum_inline (ip, &c_sum);\n",
    "    ip->check = c_sum;\n",
    "    udp->check = 0;\n",
    "    udp->source = tn->source_port;\n",
    "    udp->dest = BE_GENEVE_DSTPORT;\n",
    "    udp->len = bpf_htons (outer_udp_payload);\n",
    "    __builtin_memset (geneve, 0, gnv_hdr_size);\n",
    "    geneve->opt_len = 0 / 4;\n",
    "    geneve->ver = 0;\n",
    "    geneve->rsvd1 = 0;\n",
    "    geneve->rsvd2 = 0;\n",
    "    geneve->oam = 0;\n",
    "    geneve->critical = 0;\n",
    "    geneve->proto_type = bpf_htons (ETH_P_TEB);\n",
    "    geneve->vni[0] = (__u8) (tn->vlan_id >> 16);\n",
    "    geneve->vni[1] = (__u8) (tn->vlan_id >> 8);\n",
    "    geneve->vni[2] = (__u8) tn->vlan_id;\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_memset",
    "set_dst_mac",
    "mptm_print",
    "set_src_mac",
    "bpf_htons",
    "ipv4_csum_inline"
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
static __ALWAYS_INLINE__ int __encap_geneve(struct xdp_md *ctx,
                                          struct ethhdr *eth,
                                          geneve_tunnel_info* tn)
{
    int gnv_hdr_size = sizeof(struct genevehdr);
    int udp_hdr_size = sizeof(struct udphdr);
    int ip_hdr_size  = sizeof(struct iphdr);
    int eth_hdr_size = sizeof(struct ethhdr);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int old_size = (int)(data_end - data);

    struct ethhdr *eth_inner_hdr = (struct ethhdr *)data;
    if (eth_inner_hdr + 1 > data_end ){
        mptm_print("[Agent: ] ABORTED: Bad ETH header offset \n");
        return XDP_ABORTED;
    }

    //TODO: Read from arp map table
    set_dst_mac(data, tn->inner_dest_mac);

    int outer_hdr_size =
        gnv_hdr_size + udp_hdr_size + ip_hdr_size + eth_hdr_size;

    long ret = bpf_xdp_adjust_head(ctx, (0-outer_hdr_size));
    if (ret != 0l) {
        mptm_print("[Agent:] DROP (BUG): Failure adjusting packet header!\n");
        return XDP_DROP;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *ethcpy;
    ethcpy = data;

    if (ethcpy + 1 > data_end ) {
        mptm_print("[Agent: ] ABORTED: Bad ETH header offset \n");
        return XDP_ABORTED;
    }
    struct iphdr *ip = (struct iphdr *)(ethcpy + 1);
    if (ip + 1 > data_end){
        mptm_print("ABORTED: Bad ip header offset ip: %x data_end:%x \n", ip+1, data_end);
        return XDP_ABORTED;
    }
    struct udphdr *udp = (struct udphdr*)(ip + 1);
    if (udp + 1 > data_end){
        mptm_print("ABORTED: Bad udp header offset \n");
        return XDP_ABORTED;
    }
    struct genevehdr *geneve = (struct genevehdr*)(udp +1);
    if (geneve + 1 > data_end){
        mptm_print("ABORTED: Bad GENEVE header offset \n");
        return XDP_ABORTED;
    }

    //TODO: Attach options
    //pkt->rts_opt = (void *)&pkt->geneve->options[0];

    // Populate the outer header fields 
    ethcpy->h_proto = BE_ETH_P_IP;
    set_dst_mac(data, tn->dest_mac);
    set_src_mac(data, tn->source_mac);
    
    int outer_ip_payload = gnv_hdr_size + udp_hdr_size + ip_hdr_size + old_size;
    int outer_udp_payload = gnv_hdr_size + udp_hdr_size + old_size;

    ip->version = 4;
    ip->ihl = ip_hdr_size >> 2;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->tos = 0;
    ip->tot_len = bpf_htons(outer_ip_payload);
 
    ip->daddr = tn->dest_addr;
    ip->saddr = tn->source_addr;
    ip->ttl = DEFAULT_TTL;
        
    __u64 c_sum = 0;
    ipv4_csum_inline(ip, &c_sum);
    ip->check = c_sum;

    //TODO: Put right checksum.
    //For now make check 0
    udp->check = 0;
    udp->source = tn->source_port; // TODO: a hash value based on inner IP packet
    udp->dest = BE_GENEVE_DSTPORT;
    udp->len = bpf_htons(outer_udp_payload);

    __builtin_memset(geneve, 0, gnv_hdr_size);

    //TODO: Need to support geneve options
    //geneve->opt_len = gnv_opt_size / 4;
    geneve->opt_len = 0 / 4;
    geneve->ver = 0;
    geneve->rsvd1 = 0;
    geneve->rsvd2 = 0;
    geneve->oam = 0;
    geneve->critical = 0;
    geneve->proto_type = bpf_htons(ETH_P_TEB);

    //TODO: make vni paramater
    //trn_tunnel_id_to_vni(tn->vlid, pkt->geneve->vni);

    geneve->vni[0] = (__u8)(tn->vlan_id >> 16);
    geneve->vni[1] = (__u8)(tn->vlan_id >> 8);
    geneve->vni[2] = (__u8)tn->vlan_id;
    return XDP_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 194,
  "endLine": 200,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "encap_geneve",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " struct ethhdr *eth",
    " mptm_tunnel_info *tn"
  ],
  "output": "static__ALWAYS_INLINE__int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "cgroup_skb",
    "sched_cls",
    "sk_skb",
    "tracepoint",
    "kprobe",
    "cgroup_sock",
    "cgroup_sysctl",
    "sk_reuseport",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_out",
    "lwt_in",
    "cgroup_device",
    "flow_dissector",
    "perf_event",
    "xdp",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "lwt_seg6local",
    "sock_ops",
    "lwt_xmit",
    "sched_act"
  ],
  "source": [
    "static __ALWAYS_INLINE__ int encap_geneve (struct xdp_md *ctx, struct ethhdr *eth, mptm_tunnel_info *tn)\n",
    "{\n",
    "    struct geneve_info *geneve = (geneve_tunnel_info *) (&tn->tnl_info.geneve);\n",
    "    return __encap_geneve (ctx, eth, geneve);\n",
    "}\n"
  ],
  "called_function_list": [
    "__encap_geneve"
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
static __ALWAYS_INLINE__ int encap_geneve(struct xdp_md *ctx,
                                        struct ethhdr *eth,
                                        mptm_tunnel_info *tn) {
     // typecast the union to geneve
    struct geneve_info *geneve = (geneve_tunnel_info *)(&tn->tnl_info.geneve);
    return __encap_geneve(ctx, eth, geneve);
}

/* Use bpf.h function bpf_skb_vlan_push to remove dependency on xdp tutorials */
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
          "Function Name": "XDP_ABORTED",
          "Return": 0,
          "Description": "which serves denoting an exception like state from the program and has the same behavior as XDP_DROP only that XDP_ABORTED passes the trace_xdp_exception tracepoint which can be additionally monitored to detect misbehavior.",
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
    }
  ],
  "helperCallParams": {},
  "startLine": 203,
  "endLine": 214,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/lib/pkt-encap.h",
  "funcName": "encap_vlan",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " struct ethhdr *eth",
    " mptm_tunnel_info *tn"
  ],
  "output": "static__ALWAYS_INLINE__int",
  "helper": [
    "XDP_ABORTED",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __ALWAYS_INLINE__ int encap_vlan (struct xdp_md *ctx, struct ethhdr *eth, mptm_tunnel_info *tn)\n",
    "{\n",
    "    struct vlan_info *vlan = (vlan_tunnel_info *) (&tn->tnl_info.vlan);\n",
    "    if (vlan_tag_push (ctx, eth, vlan->vlan_id) != 0) {\n",
    "        mptm_print (\"[ERR] vlan tag push failed %d\\n\", vlan->vlan_id);\n",
    "        return XDP_ABORTED;\n",
    "    }\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "mptm_print",
    "vlan_tag_push"
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
static __ALWAYS_INLINE__ int encap_vlan(struct xdp_md *ctx,
                                      struct ethhdr *eth,
                                      mptm_tunnel_info *tn) {
    // typecast the union to vlan
    struct vlan_info *vlan = (vlan_tunnel_info *)(&tn->tnl_info.vlan);

    if (vlan_tag_push(ctx, eth, vlan->vlan_id) != 0) {
        mptm_print("[ERR] vlan tag push failed %d\n", vlan->vlan_id);
        return XDP_ABORTED;
    }
    return XDP_PASS;
}

#endif /*  __PKT_ENCAP_H__ */
