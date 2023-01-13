/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_OVERLOADABLE_SKB_H_
#define __LIB_OVERLOADABLE_SKB_H_

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 7,
 Endline: 17,
 Funcname: bpf_clear_meta,
 Input: (struct  __sk_buff *ctx),
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
bpf_clear_meta(struct __sk_buff *ctx)
{
	__u32 zero = 0;

	WRITE_ONCE(ctx->cb[0], zero);
	WRITE_ONCE(ctx->cb[1], zero);
	WRITE_ONCE(ctx->cb[2], zero);
	WRITE_ONCE(ctx->cb[3], zero);
	WRITE_ONCE(ctx->cb[4], zero);
}

/**
 * get_identity - returns source identity from the mark field
 */
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 22,
 Endline: 26,
 Funcname: get_identity,
 Input: (const struct  __sk_buff *ctx),
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
get_identity(const struct __sk_buff *ctx)
{
	return ((ctx->mark & 0xFF) << 16) | ctx->mark >> 16;
}

/**
 * get_epid - returns source endpoint identity from the mark field
 */
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 31,
 Endline: 35,
 Funcname: get_epid,
 Input: (const struct  __sk_buff *ctx),
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
get_epid(const struct __sk_buff *ctx)
{
	return ctx->mark >> 16;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 37,
 Endline: 41,
 Funcname: set_encrypt_dip,
 Input: (struct  __sk_buff *ctx, __u32 ip_endpoint),
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
set_encrypt_dip(struct __sk_buff *ctx, __u32 ip_endpoint)
{
	ctx->cb[4] = ip_endpoint;
}

/**
 * set_identity_mark - pushes 24 bit identity into ctx mark value.
 */
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 46,
 Endline: 51,
 Funcname: set_identity_mark,
 Input: (struct  __sk_buff *ctx, __u32 identity),
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
set_identity_mark(struct __sk_buff *ctx, __u32 identity)
{
	ctx->mark = ctx->mark & MARK_MAGIC_KEY_MASK;
	ctx->mark |= ((identity & 0xFFFF) << 16) | ((identity & 0xFF0000) >> 16);
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 53,
 Endline: 57,
 Funcname: set_identity_meta,
 Input: (struct  __sk_buff *ctx, __u32 identity),
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
set_identity_meta(struct __sk_buff *ctx, __u32 identity)
{
	ctx->cb[1] = identity;
}

/**
 * set_encrypt_key - pushes 8 bit key and encryption marker into ctx mark value.
 */
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 62,
 Endline: 66,
 Funcname: set_encrypt_key_mark,
 Input: (struct  __sk_buff *ctx, __u8 key),
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
set_encrypt_key_mark(struct __sk_buff *ctx, __u8 key)
{
	ctx->mark = or_encrypt_key(key);
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 68,
 Endline: 72,
 Funcname: set_encrypt_key_meta,
 Input: (struct  __sk_buff *ctx, __u8 key),
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
set_encrypt_key_meta(struct __sk_buff *ctx, __u8 key)
{
	ctx->cb[0] = or_encrypt_key(key);
}

/**
 * set_encrypt_mark - sets the encryption mark to make skb to match ip rule
 * used to steer packet into Wireguard tunnel device (cilium_wg0) in order to
 * encrypt it.
 */
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 79,
 Endline: 83,
 Funcname: set_encrypt_mark,
 Input: (struct  __sk_buff *ctx),
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
set_encrypt_mark(struct __sk_buff *ctx)
{
	ctx->mark |= MARK_MAGIC_ENCRYPT;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 85,
 Endline: 99,
 Funcname: redirect_self,
 Input: (const struct  __sk_buff *ctx),
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
redirect_self(const struct __sk_buff *ctx)
{
	/* Looping back the packet into the originating netns. In
	 * case of veth, it's xmit'ing into the hosts' veth device
	 * such that we end up on ingress in the peer. For ipvlan
	 * slave it's redirect to ingress as we are attached on the
	 * slave in netns already.
	 */
#ifdef ENABLE_HOST_REDIRECT
	return ctx_redirect(ctx, ctx->ifindex, 0);
#else
	return ctx_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 101,
 Endline: 107,
 Funcname: ctx_skip_nodeport_clear,
 Input: (struct  __sk_buff * ctx __maybe_unused),
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
ctx_skip_nodeport_clear(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 109,
 Endline: 115,
 Funcname: ctx_skip_nodeport_set,
 Input: (struct  __sk_buff * ctx __maybe_unused),
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
ctx_skip_nodeport_set(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	ctx->tc_index |= TC_INDEX_F_SKIP_NODEPORT;
#endif
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 117,
 Endline: 127,
 Funcname: ctx_skip_nodeport,
 Input: (struct  __sk_buff * ctx __maybe_unused),
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
ctx_skip_nodeport(struct __sk_buff *ctx __maybe_unused)
{
#ifdef ENABLE_NODEPORT
	volatile __u32 tc_index = ctx->tc_index;
	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
#else
	return true;
#endif
}

#ifdef ENABLE_HOST_FIREWALL
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 130,
 Endline: 134,
 Funcname: ctx_skip_host_fw_set,
 Input: (struct  __sk_buff *ctx),
 Output: static__always_inlinevoid,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline void
ctx_skip_host_fw_set(struct __sk_buff *ctx)
{
	ctx->tc_index |= TC_INDEX_F_SKIP_HOST_FIREWALL;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 136,
 Endline: 143,
 Funcname: ctx_skip_host_fw,
 Input: (struct  __sk_buff *ctx),
 Output: static__always_inlinebool,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline bool
ctx_skip_host_fw(struct __sk_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;

	ctx->tc_index &= ~TC_INDEX_F_SKIP_HOST_FIREWALL;
	return tc_index & TC_INDEX_F_SKIP_HOST_FIREWALL;
}
#endif /* ENABLE_HOST_FIREWALL */

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 146,
 Endline: 152,
 Funcname: ctx_get_xfer,
 Input: (struct  __sk_buff *ctx),
 Output: static__always_inline__maybe_unused__u32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused __u32 ctx_get_xfer(struct __sk_buff *ctx)
{
	__u32 *data_meta = ctx_data_meta(ctx);
	void *data = ctx_data(ctx);

	return !ctx_no_room(data_meta + 1, data) ? data_meta[0] : 0;
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 154,
 Endline: 158,
 Funcname: ctx_set_xfer,
 Input: (struct  __sk_buff * ctx __maybe_unused, __u32 meta __maybe_unused),
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
ctx_set_xfer(struct __sk_buff *ctx __maybe_unused, __u32 meta __maybe_unused)
{
	/* Only possible from XDP -> SKB. */
}

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/lib/overloadable_skb.h,
 Startline: 160,
 Endline: 164,
 Funcname: ctx_change_head,
 Input: (struct  __sk_buff *ctx, __u32 head_room, __u64 flags),
 Output: static__always_inline__maybe_unusedint,
 Helpers: [skb_change_head,],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused int
ctx_change_head(struct __sk_buff *ctx, __u32 head_room, __u64 flags)
{
	return skb_change_head(ctx, head_room, flags);
}

#endif /* __LIB_OVERLOADABLE_SKB_H_ */
