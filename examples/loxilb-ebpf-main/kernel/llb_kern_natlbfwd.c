/*
 *  llb_kern_nat.c: LoxiLB Kernel eBPF Stateful NAT/LB Processing
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
static int __always_inline
dp_sel_nat_ep(void *ctx, struct dp_nat_tacts *act)
{
  int sel = -1;
  uint8_t n = 0;
  uint16_t i = 0;
  struct mf_xfrm_inf *nxfrm_act;

  if (act->sel_type == NAT_LB_SEL_RR) {
    bpf_spin_lock(&act->lock);
    i = act->sel_hint; 

    while (n < LLB_MAX_NXFRMS) {
      if (i >= 0 && i < LLB_MAX_NXFRMS) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act < act + 1) {
          if (nxfrm_act->inactive == 0) { 
            act->sel_hint = (i + 1) % act->nxfrm;
            sel = i;
            break;
          }
        }
      }
      i++;
      i = i % act->nxfrm;
      n++;
    }
    bpf_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_HASH) {
    sel = dp_get_pkt_hash(ctx) % act->nxfrm;
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      /* Fall back if hash selection gives us a deadend */
      if (act->nxfrms[sel].inactive) {
        for (i = 0; i < LLB_MAX_NXFRMS; i++) {
          if (act->nxfrms[i].inactive == 0) {
            sel = i;
            break;
          }
        }
      }
    }
  }

  LL_DBG_PRINTK("lb-sel %d", sel);

  return sel;
}

static int __always_inline
dp_do_nat(void *ctx, struct xfi *xf)
{
  struct dp_nat_key key;
  struct mf_xfrm_inf *nxfrm_act;
  struct dp_nat_tacts *act;
  __u32 sel;

  memset(&key, 0, sizeof(key));
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  if (xf->l34m.nw_proto != IPPROTO_ICMP) {
    key.dport = xf->l34m.dest;
  } else {
    key.dport = 0;
  }
  key.zone = xf->pm.zone;
  key.l4proto = xf->l34m.nw_proto;
  key.mark = (__u16)(xf->pm.dp_mark & 0xffff);
  if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
    key.v6 = 1;
  }

  LL_DBG_PRINTK("[NAT] --Lookup\n");

  xf->pm.table_id = LL_DP_NAT_MAP;

  act = bpf_map_lookup_elem(&nat_map, &key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~LLB_NAT_SRC;
    return 0;
  }

  LL_DBG_PRINTK("[NAT] action %d pipe %x\n",
                 act->ca.act_type, xf->pm.pipe_act);

  if (act->ca.act_type == DP_SET_SNAT || 
      act->ca.act_type == DP_SET_DNAT) {
    sel = dp_sel_nat_ep(ctx, act);

    xf->nm.dsr = act->ca.oaux ? 1: 0;
    xf->pm.nf = act->ca.act_type == DP_SET_SNAT ? LLB_NAT_SRC : LLB_NAT_DST;

    /* FIXME - Do not select inactive end-points 
     * Need multi-passes for selection
     */
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      nxfrm_act = &act->nxfrms[sel];

      if (nxfrm_act < act + 1) {
        DP_XADDR_CP(xf->nm.nxip, nxfrm_act->nat_xip);
        DP_XADDR_CP(xf->nm.nrip, nxfrm_act->nat_rip);
        xf->nm.nxport = nxfrm_act->nat_xport;
        xf->nm.nv6 = nxfrm_act->nv6 ? 1: 0;
        xf->nm.sel_aid = sel;
        xf->nm.ito = act->ito;
        xf->pm.rule_id =  act->ca.cidx;
        LL_DBG_PRINTK("[NAT] ACT %x\n", xf->pm.nf);
        /* Special case related to host-dnat */
        if (xf->l34m.saddr4 == xf->nm.nxip4 && xf->pm.nf == LLB_NAT_DST) {
          xf->nm.nxip4 = 0;
        }
      }
    } else {
      xf->pm.nf = 0;
    }
  } else { 
    LLBS_PPLN_DROP(xf);
  }

  return 1;
}
