/*
 *  llb_kern_sess.c: LoxiLB kernel eBPF Subscriber Session Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

static int __always_inline
dp_pipe_set_rm_gtp_tun(void *ctx, struct xfi *xf)
{
  LL_DBG_PRINTK("[SESS] rm-gtp \n");
  dp_pop_outer_metadata(ctx, xf, 0);
  xf->tm.tun_type = LLB_TUN_GTP;
  return 0;
}

static int __always_inline
dp_pipe_set_rm_ipip_tun(void *ctx, struct xfi *xf)
{
  LL_DBG_PRINTK("[SESS] rm-ipip \n");
  dp_pop_outer_metadata(ctx, xf, 0);
  xf->tm.tun_type = LLB_TUN_IPIP;
  return 0;
}

static int __always_inline
dp_do_sess4_lkup(void *ctx, struct xfi *xf)
{
  struct dp_sess4_key key;
  struct dp_sess_tact *act;

  key.r = 0;
  if (xf->tm.tunnel_id && xf->tm.tun_type != LLB_TUN_IPIP) {
    key.daddr = xf->il34m.daddr4;
    key.saddr = xf->il34m.saddr4;
    key.teid = bpf_ntohl(xf->tm.tunnel_id);
  } else {
    if (xf->pm.nf == LLB_NAT_SRC) {
      key.saddr = xf->nm.nxip4;
      key.daddr = xf->l34m.daddr4;
    } else if (xf->pm.nf == LLB_NAT_DST) {
      key.daddr = xf->nm.nxip4;
      key.saddr = xf->l34m.saddr4;
    } else {
      key.daddr = xf->l34m.daddr4;
      key.saddr = xf->l34m.saddr4;
    }
    key.teid = 0;
  }

  LL_DBG_PRINTK("[SESS4] -- Lookup\n");
  LL_DBG_PRINTK("[SESS4] daddr %x\n", key.daddr);
  LL_DBG_PRINTK("[SESS4] saddr %x\n", key.saddr);
  LL_DBG_PRINTK("[SESS4] teid 0x%x\n", key.teid);

  xf->pm.table_id = LL_DP_SESS4_MAP;

  act = bpf_map_lookup_elem(&sess_v4_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[SESS4] miss");
    return 0;
  }

  xf->pm.phit |= LLB_DP_SESS_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_SESS4_STATS_MAP, act->ca.cidx);

  if (act->ca.act_type == DP_SET_DROP) {
    goto drop;
  } else if (act->ca.act_type == DP_SET_RM_GTP) {
    dp_pipe_set_rm_gtp_tun(ctx, xf);
    xf->qm.qfi = act->qfi;
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else if (act->ca.act_type == DP_SET_RM_IPIP) {
    dp_pipe_set_rm_ipip_tun(ctx, xf);
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else {
    xf->tm.new_tunnel_id = act->teid;
    xf->tm.tun_type = LLB_TUN_GTP;
    xf->qm.qfi = act->qfi;
    xf->tm.tun_rip = act->rip;
    xf->tm.tun_sip = act->sip;
  }

  return 0;

drop:
  LLBS_PPLN_DROP(xf);
  return 0;
}
