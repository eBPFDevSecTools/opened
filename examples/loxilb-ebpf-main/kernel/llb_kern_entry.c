/*
 *  llb_kern_entry.c: LoxiLB Kernel eBPF entry points
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_pdi.h"
#include "../common/llb_dpapi.h"

#include "llb_kern_cdefs.h"
#include "llb_kern_sum.c"
#include "llb_kern_compose.c"
#include "llb_kern_policer.c"
#include "llb_kern_sessfwd.c"
#include "llb_kern_fw.c"
#include "llb_kern_ct.c"
#include "llb_kern_natlbfwd.c"
#include "llb_kern_l3fwd.c"
#include "llb_kern_l2fwd.c"
#include "llb_kern_devif.c"
#include "llb_kern_fcfwd.c"

static int __always_inline
dp_ing_pkt_main(void *md, struct xfi *xf)
{
  LL_DBG_PRINTK("[PRSR] START cpu %d \n", bpf_get_smp_processor_id());
  LL_DBG_PRINTK("[PRSR] fi  %d\n", sizeof(*xf));
  LL_DBG_PRINTK("[PRSR] fm  %d\n", sizeof(xf->fm));
  LL_DBG_PRINTK("[PRSR] l2m %d\n", sizeof(xf->l2m));
  LL_DBG_PRINTK("[PRSR] l34m %d\n", sizeof(xf->l34m));
  LL_DBG_PRINTK("[PRSR] tm  %d\n", sizeof(xf->tm));
  LL_DBG_PRINTK("[PRSR] qm  %d\n", sizeof(xf->qm));

  dp_parse_d0(md, xf, 0);

  /* Handle parser results */
  if (xf->pm.pipe_act & LLB_PIPE_REWIRE) {
    return dp_rewire_packet(md, xf);
  } else if (xf->pm.pipe_act & LLB_PIPE_RDR) {
    return dp_redir_packet(md, xf);
  }

  if (xf->pm.pipe_act & LLB_PIPE_PASS ||
      xf->pm.pipe_act & LLB_PIPE_TRAP) {
    return DP_PASS;
  }

  return dp_ing_slow_main(md, xf);
}

#ifndef LL_TC_EBPF
SEC("xdp_packet_hook")
int  xdp_packet_func(struct xdp_md *ctx)
{
  int z = 0;
  struct xfi *xf;

  LL_FC_PRINTK("[PRSR] xdp start\n");

  xf = bpf_map_lookup_elem(&xfis, &z);
  if (!xf) {
    return DP_DROP;
  }
  memset(xf, 0, sizeof *xf);

  dp_parse_d0(ctx, xf, 0);

  return DP_PASS;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
  return dp_ing_pass_main(ctx);
}

#else

static int __always_inline
tc_packet_func__(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  memset(xf, 0, sizeof(*xf));
  xf->pm.tc = 1;

  return dp_ing_pkt_main(md, xf);
}

SEC("tc_packet_hook0")
int tc_packet_func_fast(struct __sk_buff *md)
{
#ifdef HAVE_DP_FC
  struct xfi *xf;

  DP_NEW_FCXF(xf);

#ifdef HAVE_DP_EGR_HOOK
  if (DP_LLB_INGP(md)) {
    return DP_PASS;
  }
#endif

  dp_parse_d0(md, xf, 1);

  return dp_ing_fc_main(md, xf);
#else
  return tc_packet_func__(md);
#endif
}

SEC("tc_packet_hook1")
int tc_packet_func(struct __sk_buff *md)
{
  return tc_packet_func__(md);
}

SEC("tc_packet_hook2")
int tc_packet_func_slow(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_ing_ct_main(md, xf);
}

SEC("tc_packet_hook3")
int tc_packet_func_fw(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_do_fw_main(md, xf);
}

SEC("tc_packet_hook4")
int tc_csum_func1(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_sctp_csum(md, xf);
}

SEC("tc_packet_hook5")
int tc_csum_func2(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_sctp_csum(md, xf);
}

SEC("tc_packet_hook6")
int tc_slow_unp_func(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_unparse_packet_always_slow(md, xf);
}

#endif
