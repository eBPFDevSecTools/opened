/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_XDP_H_
#define __LIB_OVERLOADABLE_XDP_H_

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 7,
 Endline: 10,
 Funcname: bpf_clear_meta,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
bpf_clear_meta(struct xdp_md *ctx __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 12,
 Endline: 16,
 Funcname: get_identity,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused int
get_identity(struct xdp_md *ctx __maybe_unused)
{
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 18,
 Endline: 22,
 Funcname: set_encrypt_dip,
 Input: (struct xdp_md * ctx __maybe_unused, __u32 ip_endpoint __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
set_encrypt_dip(struct xdp_md *ctx __maybe_unused,
		__u32 ip_endpoint __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 24,
 Endline: 27,
 Funcname: set_identity_mark,
 Input: (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
set_identity_mark(struct xdp_md *ctx __maybe_unused, __u32 identity __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 29,
 Endline: 33,
 Funcname: set_identity_meta,
 Input: (struct xdp_md * ctx __maybe_unused, __u32 identity __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
set_identity_meta(struct xdp_md *ctx __maybe_unused,
		__u32 identity __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 35,
 Endline: 38,
 Funcname: set_encrypt_key_mark,
 Input: (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
set_encrypt_key_mark(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 40,
 Endline: 43,
 Funcname: set_encrypt_key_meta,
 Input: (struct xdp_md * ctx __maybe_unused, __u8 key __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
set_encrypt_key_meta(struct xdp_md *ctx __maybe_unused, __u8 key __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 45,
 Endline: 53,
 Funcname: redirect_self,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedint,
 Helpers: [redirect,],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused int
redirect_self(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_HOST_REDIRECT
	return XDP_TX;
#else
	return -ENOTSUP;
#endif
}

#define RECIRC_MARKER	5 /* tail call recirculation */
#define XFER_MARKER	6 /* xdp -> skb meta transfer */

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 58,
 Endline: 64,
 Funcname: ctx_skip_nodeport_clear,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
ctx_skip_nodeport_clear(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 0);
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 66,
 Endline: 72,
 Funcname: ctx_skip_nodeport_set,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void
ctx_skip_nodeport_set(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx_store_meta(ctx, RECIRC_MARKER, 1);
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 74,
 Endline: 82,
 Funcname: ctx_skip_nodeport,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unusedbool,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused bool
ctx_skip_nodeport(struct xdp_md *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	return ctx_load_meta(ctx, RECIRC_MARKER);
#else
	return true;
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 84,
 Endline: 88,
 Funcname: ctx_get_xfer,
 Input: (struct xdp_md * ctx __maybe_unused),
 Output: static__always_inline__maybe_unused__u32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused __u32
ctx_get_xfer(struct xdp_md *ctx __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 90,
 Endline: 94,
 Funcname: ctx_set_xfer,
 Input: (struct xdp_md *ctx, __u32 meta),
 Output: static__always_inline__maybe_unusedvoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused void ctx_set_xfer(struct xdp_md *ctx,
							__u32 meta)
{
	ctx_store_meta(ctx, XFER_MARKER, meta);
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_xdp.h,
 Startline: 96,
 Endline: 102,
 Funcname: ctx_change_head,
 Input: (struct xdp_md * ctx __maybe_unused, __u32 head_room __maybe_unused, __u64 flags __maybe_unused),
 Output: static__always_inline__maybe_unusedint,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused int
ctx_change_head(struct xdp_md *ctx __maybe_unused,
		__u32 head_room __maybe_unused,
		__u64 flags __maybe_unused)
{
	return 0; /* Only intended for SKB context. */
}

#endif /* __LIB_OVERLOADABLE_XDP_H_ */
