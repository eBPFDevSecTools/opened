/* SPDX-License-Identifier: GPL-2.0 */

#include "decap_kern.c"

//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>

/*
 OPENED COMMENT BEGIN
 File: /home/sayandes/codequery/katran/x.c
 Startline: 8
 Endline: 13
 Funcname: xdp_prog_simple
 Input: (struct xdp_md *ctx)
 Output: int
 Helpers: []
 Read_maps: []
 Update_maps: []
 Func Description: Same as decap_kern, it decaps the packet and pass it to the tcp/ip stack.
 OPENED COMMENT END
 */
SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
  return xdpdecap(ctx);
//return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
