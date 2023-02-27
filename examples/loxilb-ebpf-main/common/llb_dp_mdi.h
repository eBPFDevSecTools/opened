/*
 * llb_dp_mdi.h: LoxiLB DP Private Definitions
 * Copyright (C) 2022,  NetLOX <www.netlox.io>
 *
 * SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) 
 */
#ifndef __LLB_DP_MDI_H__ 
#define __LLB_DP_MDI_H__

#define DP_BUF_DATA(F)        (DP_TC_PTR(F->fm.data))
#define DP_BUF_DATA_END(F)    (DP_TC_PTR(F->fm.data_end))

#ifndef MAX_STACKED_VLANS
#define MAX_STACKED_VLANS     2
#endif

#define LLB_INGP_MARK         0xf01dab1e

#define LLBS_PPLN_DROP(F)     (F->pm.pipe_act |= LLB_PIPE_DROP);
#define LLBS_PPLN_TRAP(F)     (F->pm.pipe_act |= LLB_PIPE_TRAP);
#define LLBS_PPLN_RDR(F)      (F->pm.pipe_act |= LLB_PIPE_RDR);
#define LLBS_PPLN_RDR_PRIO(F) (F->pm.pipe_act |= LLB_PIPE_RDR_PRIO);
#define LLBS_PPLN_REWIRE(F)   (F->pm.pipe_act |= LLB_PIPE_REWIRE);
#define LLBS_PPLN_PASS(F)     (F->pm.pipe_act |= LLB_PIPE_PASS);
#define LLBS_PPLN_SETCT(F)    (F->pm.pipe_act |= LLB_PIPE_SET_CT);

#define LLBS_PPLN_TRAPC(F,C)          \
do {                                  \
  F->pm.pipe_act |= LLB_PIPE_TRAP;    \
  F->pm.rcode = C;                    \
} while (0)

#define LL_PIPE_FC_CAP(x)                     \
  ((x)->pm.pipe_act == LLB_PIPE_RDR &&        \
  (x)->pm.phit & LLB_DP_ACL_HIT &&            \
  !((x)->pm.phit & LLB_DP_SESS_HIT) &&        \
  !((x)->tm.tun_type == LLB_TUN_IPIP) &&      \
  (x)->l2m.dl_type == bpf_htons(ETH_P_IP) &&  \
  (x)->qm.ipolid == 0 &&                      \
  (x)->nm.xlate_proto == 0 &&                 \
  (x)->pm.dp_rec == 0 &&                      \
  (x)->pm.mirr == 0)

#define LL_PIPELINE_CONT(F) (!F->pm.pipe_act)

#ifdef LL_DP_DEBUG 
#define LL_DBG_PRINTK bpf_printk
#else
#define LL_DBG_PRINTK(fmt, ...)  do { } while (0) 
#endif

#ifdef LL_FC_XDP_DEBUG 
#define LL_FC_PRINTK bpf_printk
#else
#define LL_FC_PRINTK(fmt, ...)  do { } while (0) 
#endif

#define LLB_PIPE_RDR_MASK     (LLB_PIPE_RDR | LLB_PIPE_RDR_PRIO)

struct dp_pi_mdi {
    /* Pipeline Metadata */
    __u16            bd;
    __u16            py_bytes;
#define LLB_PIPE_TRAP         0x1
#define LLB_PIPE_DROP         0x2
#define LLB_PIPE_RDR          0x4
#define LLB_PIPE_PASS         0x8
#define LLB_PIPE_REWIRE       0x10
#define LLB_PIPE_RDR_PRIO     0x20
#define LLB_PIPE_SET_CT       0x40      
    __u8             pipe_act;
#define LLB_PIPE_RC_PARSER    0x1
#define LLB_PIPE_RC_ACL_MISS  0x2
#define LLB_PIPE_RC_TUN_DECAP 0x4 
#define LLB_PIPE_RC_FW_RDR    0x8 
    __u8             rcode;
    __u8             tc;
    __u8             l3_off;
    __u16            nh_num;
    __u16            qos_id;
#define LLB_DP_TMAC_HIT       0x1
#define LLB_DP_ACL_HIT        0x2
#define LLB_XDP_PDR_HIT       0x4
#define LLB_XDP_RT_HIT        0x8
#define LLB_DP_FC_HIT         0x10
#define LLB_DP_SESS_HIT       0x20
#define LLB_DP_RES_HIT        0x40
#define LLB_DP_FW_HIT         0x80
    __u8             phit;
#define LLB_DP_PORT_UPP       0x1
    __u8             pprop;
    __u8             lkup_dmac[6];
    __u16            iport;
    __u16            oport;

    __u32            sess_id;
    __u16            zone;
    __u8             l4_off;
    __u8             table_id;
#define LLB_MIRR_MARK         0xdeadbeef
    __u16            mirr;
#define LLB_TCP_FIN           0x01
#define LLB_TCP_SYN           0x02
#define LLB_TCP_RST           0x04
#define LLB_TCP_PSH           0x08
#define LLB_TCP_ACK           0x10
#define LLB_TCP_URG           0x20
    __u8             tcp_flags;
#define LLB_NAT_DST           0x01
#define LLB_NAT_SRC           0x02
#define LLB_NAT_HDST          0x04
#define LLB_NAT_HSRC          0x08
    __u8             nf;
    __u32            rule_id;
    __u8             il3_off;
    __u8             il4_off;
    __u8             itcp_flags;
    __u8             l4fin:4;
    __u8             il4fin:4;
    __u16            l3_len;
    __u16            l3_plen;
    __u16            il3_len;
    __u16            il3_plen;
    __u16            dp_mark;
    __u16            dp_rec;
    __u16            tun_off;
    __u16            fw_mid;
    __u16            fw_lid;
    __u16            fw_rid;
}__attribute__((packed));

struct dp_fr_mdi {
    __u32            dat;
    __u32            dat_end;
};

struct dp_l2_mdi {
    __u16            vlan[MAX_STACKED_VLANS]; 
    __u16            dl_type;
    __u8             dl_dst[6];
    __u8             dl_src[6];
    __u8             vlan_pcp;
    __u8             valid;
    __u16            res;
};

#define saddr4 saddr[0]
#define daddr4 daddr[0]

struct dp_l34_mdi {
    __u8             tos;
    __u8             nw_proto;

    __u8             valid;
    __u8             r;

    __u16            source;
    __u16            dest;

    __u32            seq;
    __u32            ack;

    __u32            saddr[4];
    __u32            daddr[4];
};

struct dp_tun_mdi {
    __u32            new_tunnel_id;
    __u16            tun_encap;
    __u16            tun_decap;
    __le32           tunnel_id;
#define LLB_TUN_VXLAN         1
#define LLB_TUN_GTP           2
#define LLB_TUN_STT           3
#define LLB_TUN_GRE           4
#define LLB_TUN_IPIP          5
    __u32            tun_type;
    __le32           tun_rip;
    __le32           tun_sip; 
};

#define  LLB_PIPE_COL_NONE    0 
#define  LLB_PIPE_COL_GREEN   1
#define  LLB_PIPE_COL_YELLOW  2
#define  LLB_PIPE_COL_RED     3

struct dp_qos_mdi {
    __u8             tc;
    __u8             icol;
    __u8             ocol;
    __u8             qfi;
    __u16            ipolid;
    __u16            opolid;
};

#define nxip4 nxip[0]
#define nrip4 nrip[0]

struct dp_nat_mdi {
    __u32            nxip[4];      /* NAT xIP */
    __u32            nrip[4];      /* NAT rIP (for one-arm) */
    __u16            nxport;       /* NAT xport */
#define LLB_PIPE_CT_NONE  0
#define LLB_PIPE_CT_INP   1
#define LLB_PIPE_CT_EST   2
    __u8            ct_sts;        /* Conntrack state */
    __u8            sel_aid;
    __u8            nv6;
    __u8            xlate_proto;
    __u8            dsr;
    __u8            res;
    __u64           ito;
};

struct dp_key_mdi {
    __u8             skey[16];     /* Scratch key space */
};

struct xfi {
    struct dp_fr_mdi  fm;
    struct dp_l2_mdi  l2m;
    struct dp_l34_mdi l34m;
    struct dp_l2_mdi  il2m;
    struct dp_l34_mdi il34m;
    struct dp_tun_mdi tm;
    struct dp_nat_mdi nm;
    struct dp_key_mdi km;
    struct dp_qos_mdi qm; 

    /* Pipeline Info*/
    struct dp_pi_mdi  pm;
}__attribute__((packed));

#endif
