/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CTX_XDP_H_
#define __BPF_CTX_XDP_H_

#include <linux/if_ether.h>
#include <linux/byteorder.h>

#define __ctx_buff			xdp_md
#define __ctx_is			__ctx_xdp

#include "common.h"
#include "../helpers_xdp.h"
#include "../builtins.h"
#include "../section.h"
#include "../loader.h"
#include "../csum.h"

#define CTX_ACT_OK			XDP_PASS
#define CTX_ACT_DROP			XDP_DROP
#define CTX_ACT_TX			XDP_TX	/* hairpin only */
#define CTX_ACT_REDIRECT		XDP_REDIRECT

#define CTX_DIRECT_WRITE_OK		1

					/* cb + RECIRC_MARKER + XFER_MARKER */
#define META_PIVOT			((int)(field_sizeof(struct __sk_buff, cb) + \
					       sizeof(__u32) * 2))

/* This must be a mask and all offsets guaranteed to be less than that. */
#define __CTX_OFF_MAX			0xff

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 34,
  "endLine": 60,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "xdp_load_bytes",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx",
    " __u64 off",
    " void *to",
    " const __u64 len"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused int xdp_load_bytes (const struct xdp_md *ctx, __u64 off, void *to, const __u64 len)\n",
    "{\n",
    "    void *from;\n",
    "    int ret;\n",
    "    asm volatile (\"r1 = *(u32 *)(%[ctx] +0)\\n\\t\"\n",
    "        \"r2 = *(u32 *)(%[ctx] +4)\\n\\t\"\n",
    "        \"%[off] &= %[offmax]\\n\\t\"\n",
    "        \"r1 += %[off]\\n\\t\"\n",
    "        \"%[from] = r1\\n\\t\"\n",
    "        \"r1 += %[len]\\n\\t\"\n",
    "        \"if r1 > r2 goto +2\\n\\t\"\n",
    "        \"%[ret] = 0\\n\\t\"\n",
    "        \"goto +1\\n\\t\"\n",
    "        \"%[ret] = %[errno]\\n\\t\"\n",
    "        : [ret] \"=r\"\n",
    "        (ret), [from] \"=r\"\n",
    "        (from) : [ctx] \"r\"\n",
    "        (ctx), [off] \"r\"\n",
    "        (off), [len] \"ri\"\n",
    "        (len), [offmax] \"i\"\n",
    "        (__CTX_OFF_MAX), [errno] \"i\"\n",
    "        (- EINVAL) : \"r1\",\n",
    "        \"r2\"\n",
    "        );\n",
    "    if (!ret)\n",
    "        memcpy (to, from, len);\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
xdp_load_bytes(const struct xdp_md *ctx, __u64 off, void *to, const __u64 len)
{
	void *from;
	int ret;
	/* LLVM tends to generate code that verifier doesn't understand,
	 * so force it the way we want it in order to open up a range
	 * on the reg.
	 */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[from] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [from]"=r"(from)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 62,
  "endLine": 86,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "xdp_store_bytes",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx",
    " __u64 off",
    " const void *from",
    " const __u64 len",
    " __u64 flags __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused int xdp_store_bytes (const struct xdp_md *ctx, __u64 off, const void *from, const __u64 len, __u64 flags __maybe_unused)\n",
    "{\n",
    "    void *to;\n",
    "    int ret;\n",
    "    asm volatile (\"r1 = *(u32 *)(%[ctx] +0)\\n\\t\"\n",
    "        \"r2 = *(u32 *)(%[ctx] +4)\\n\\t\"\n",
    "        \"%[off] &= %[offmax]\\n\\t\"\n",
    "        \"r1 += %[off]\\n\\t\"\n",
    "        \"%[to] = r1\\n\\t\"\n",
    "        \"r1 += %[len]\\n\\t\"\n",
    "        \"if r1 > r2 goto +2\\n\\t\"\n",
    "        \"%[ret] = 0\\n\\t\"\n",
    "        \"goto +1\\n\\t\"\n",
    "        \"%[ret] = %[errno]\\n\\t\"\n",
    "        : [ret] \"=r\"\n",
    "        (ret), [to] \"=r\"\n",
    "        (to) : [ctx] \"r\"\n",
    "        (ctx), [off] \"r\"\n",
    "        (off), [len] \"ri\"\n",
    "        (len), [offmax] \"i\"\n",
    "        (__CTX_OFF_MAX), [errno] \"i\"\n",
    "        (- EINVAL) : \"r1\",\n",
    "        \"r2\"\n",
    "        );\n",
    "    if (!ret)\n",
    "        memcpy (to, from, len);\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
xdp_store_bytes(const struct xdp_md *ctx, __u64 off, const void *from,
		const __u64 len, __u64 flags __maybe_unused)
{
	void *to;
	int ret;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[to] = r1\n\t"
		     "r1 += %[len]\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [to]"=r"(to)
		     : [ctx]"r"(ctx), [off]"r"(off), [len]"ri"(len),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		memcpy(to, from, len);
	return ret;
}

#define ctx_load_bytes			xdp_load_bytes
#define ctx_store_bytes			xdp_store_bytes

/* Fyi, remapping to stubs helps to assert that the code is not in
 * use since it otherwise triggers a verifier error.
 */

#define ctx_change_type			xdp_change_type__stub
#define ctx_change_tail			xdp_change_tail__stub

#define ctx_pull_data(ctx, ...)		do { /* Already linear. */ } while (0)

#define ctx_get_tunnel_key		xdp_get_tunnel_key__stub
#define ctx_set_tunnel_key		xdp_set_tunnel_key__stub

#define ctx_event_output		xdp_event_output

#define ctx_adjust_meta			xdp_adjust_meta

#define get_hash(ctx)			({ 0; })
#define get_hash_recalc(ctx)		get_hash(ctx)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 110,
  "endLine": 114,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "__csum_replace_by_diff",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__sum16 *sum",
    " __wsum diff"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void __csum_replace_by_diff (__sum16 *sum, __wsum diff)\n",
    "{\n",
    "    *sum = csum_fold (csum_add (diff, ~csum_unfold (*sum)));\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused void
__csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	*sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 116,
  "endLine": 120,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "__csum_replace_by_4",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__sum16 *sum",
    " __wsum from",
    " __wsum to"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void __csum_replace_by_4 (__sum16 *sum, __wsum from, __wsum to)\n",
    "{\n",
    "    __csum_replace_by_diff (sum, csum_add (~from, to));\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused void
__csum_replace_by_4(__sum16 *sum, __wsum from, __wsum to)
{
	__csum_replace_by_diff(sum, csum_add(~from, to));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "l3_csum_replace": [
      {
        "opVar": "NA",
        "inpVar": [
          "const struct xdp_md *ctx",
          " __u64 off",
          " const __u32 from",
          "\t\t__u32 to",
          "\t\t__u32 flags"
        ]
      }
    ]
  },
  "startLine": 122,
  "endLine": 154,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "l3_csum_replace",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx",
    " __u64 off",
    " const __u32 from",
    " __u32 to",
    " __u32 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "l3_csum_replace"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __maybe_unused int l3_csum_replace (const struct xdp_md *ctx, __u64 off, const __u32 from, __u32 to, __u32 flags)\n",
    "{\n",
    "    __u32 size = flags & BPF_F_HDR_FIELD_MASK;\n",
    "    __sum16 *sum;\n",
    "    int ret;\n",
    "    if (unlikely (flags & ~(BPF_F_HDR_FIELD_MASK)))\n",
    "        return -EINVAL;\n",
    "    if (unlikely (size != 0 && size != 2))\n",
    "        return -EINVAL;\n",
    "    asm volatile (\"r1 = *(u32 *)(%[ctx] +0)\\n\\t\"\n",
    "        \"r2 = *(u32 *)(%[ctx] +4)\\n\\t\"\n",
    "        \"%[off] &= %[offmax]\\n\\t\"\n",
    "        \"r1 += %[off]\\n\\t\"\n",
    "        \"%[sum] = r1\\n\\t\"\n",
    "        \"r1 += 2\\n\\t\"\n",
    "        \"if r1 > r2 goto +2\\n\\t\"\n",
    "        \"%[ret] = 0\\n\\t\"\n",
    "        \"goto +1\\n\\t\"\n",
    "        \"%[ret] = %[errno]\\n\\t\"\n",
    "        : [ret] \"=r\"\n",
    "        (ret), [sum] \"=r\"\n",
    "        (sum) : [ctx] \"r\"\n",
    "        (ctx), [off] \"r\"\n",
    "        (off), [offmax] \"i\"\n",
    "        (__CTX_OFF_MAX), [errno] \"i\"\n",
    "        (- EINVAL) : \"r1\",\n",
    "        \"r2\"\n",
    "        );\n",
    "    if (!ret)\n",
    "        from ? __csum_replace_by_4 (sum, from, to) : __csum_replace_by_diff (sum, to);\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
l3_csum_replace(const struct xdp_md *ctx, __u64 off, const __u32 from,
		__u32 to,
		__u32 flags)
{
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret)
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
	return ret;
}

#define CSUM_MANGLED_0		((__sum16)0xffff)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "l4_csum_replace": [
      {
        "opVar": "NA",
        "inpVar": [
          "const struct xdp_md *ctx",
          " __u64 off",
          " __u32 from",
          " __u32 to",
          "\t\t__u32 flags"
        ]
      }
    ]
  },
  "startLine": 158,
  "endLine": 196,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "l4_csum_replace",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx",
    " __u64 off",
    " __u32 from",
    " __u32 to",
    " __u32 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "l4_csum_replace"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __maybe_unused int l4_csum_replace (const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to, __u32 flags)\n",
    "{\n",
    "    bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;\n",
    "    __u32 size = flags & BPF_F_HDR_FIELD_MASK;\n",
    "    __sum16 *sum;\n",
    "    int ret;\n",
    "    if (unlikely (flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK)))\n",
    "        return -EINVAL;\n",
    "    if (unlikely (size != 0 && size != 2))\n",
    "        return -EINVAL;\n",
    "    asm volatile (\"r1 = *(u32 *)(%[ctx] +0)\\n\\t\"\n",
    "        \"r2 = *(u32 *)(%[ctx] +4)\\n\\t\"\n",
    "        \"%[off] &= %[offmax]\\n\\t\"\n",
    "        \"r1 += %[off]\\n\\t\"\n",
    "        \"%[sum] = r1\\n\\t\"\n",
    "        \"r1 += 2\\n\\t\"\n",
    "        \"if r1 > r2 goto +2\\n\\t\"\n",
    "        \"%[ret] = 0\\n\\t\"\n",
    "        \"goto +1\\n\\t\"\n",
    "        \"%[ret] = %[errno]\\n\\t\"\n",
    "        : [ret] \"=r\"\n",
    "        (ret), [sum] \"=r\"\n",
    "        (sum) : [ctx] \"r\"\n",
    "        (ctx), [off] \"r\"\n",
    "        (off), [offmax] \"i\"\n",
    "        (__CTX_OFF_MAX), [errno] \"i\"\n",
    "        (- EINVAL) : \"r1\",\n",
    "        \"r2\"\n",
    "        );\n",
    "    if (!ret) {\n",
    "        if (is_mmzero && !*sum)\n",
    "            return 0;\n",
    "        from ? __csum_replace_by_4 (sum, from, to) : __csum_replace_by_diff (sum, to);\n",
    "        if (is_mmzero && !*sum)\n",
    "            *sum = CSUM_MANGLED_0;\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
l4_csum_replace(const struct xdp_md *ctx, __u64 off, __u32 from, __u32 to,
		__u32 flags)
{
	bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
	__u32 size = flags & BPF_F_HDR_FIELD_MASK;
	__sum16 *sum;
	int ret;

	if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_PSEUDO_HDR |
			       BPF_F_HDR_FIELD_MASK)))
		return -EINVAL;
	if (unlikely(size != 0 && size != 2))
		return -EINVAL;
	/* See xdp_load_bytes(). */
	asm volatile("r1 = *(u32 *)(%[ctx] +0)\n\t"
		     "r2 = *(u32 *)(%[ctx] +4)\n\t"
		     "%[off] &= %[offmax]\n\t"
		     "r1 += %[off]\n\t"
		     "%[sum] = r1\n\t"
		     "r1 += 2\n\t"
		     "if r1 > r2 goto +2\n\t"
		     "%[ret] = 0\n\t"
		     "goto +1\n\t"
		     "%[ret] = %[errno]\n\t"
		     : [ret]"=r"(ret), [sum]"=r"(sum)
		     : [ctx]"r"(ctx), [off]"r"(off),
		       [offmax]"i"(__CTX_OFF_MAX), [errno]"i"(-EINVAL)
		     : "r1", "r2");
	if (!ret) {
		if (is_mmzero && !*sum)
			return 0;
		from ? __csum_replace_by_4(sum, from, to) :
		       __csum_replace_by_diff(sum, to);
		if (is_mmzero && !*sum)
			*sum = CSUM_MANGLED_0;
	}
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "xdp_adjust_head": [
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx",
          " -len_diff"
        ]
      }
    ]
  },
  "startLine": 198,
  "endLine": 234,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_change_proto",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " const __be16 proto __maybe_unused",
    " const __u64 flags __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_change_proto (struct xdp_md * ctx __maybe_unused, const __be16 proto __maybe_unused, const __u64 flags __maybe_unused)\n",
    "{\n",
    "    const __s32 len_diff = proto == __constant_htons (ETH_P_IPV6) ? 20 : -20;\n",
    "    const __u32 move_len = 14;\n",
    "    void *data, *data_end;\n",
    "    int ret;\n",
    "    build_bug_on (flags != 0);\n",
    "    build_bug_on (proto != __constant_htons (ETH_P_IPV6) && proto != __constant_htons (ETH_P_IP));\n",
    "    if (len_diff < 0) {\n",
    "        data_end = ctx_data_end (ctx);\n",
    "        data = ctx_data (ctx);\n",
    "        if (data + move_len + -len_diff <= data_end)\n",
    "            __bpf_memmove_fwd (data + -len_diff, data, move_len);\n",
    "        else\n",
    "            return -EFAULT;\n",
    "    }\n",
    "    ret = xdp_adjust_head (ctx, - len_diff);\n",
    "    if (!ret && len_diff > 0) {\n",
    "        data_end = ctx_data_end (ctx);\n",
    "        data = ctx_data (ctx);\n",
    "        if (data + move_len + len_diff <= data_end)\n",
    "            __bpf_memmove_fwd (data, data + len_diff, move_len);\n",
    "        else\n",
    "            return -EFAULT;\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
ctx_change_proto(struct xdp_md *ctx __maybe_unused,
		 const __be16 proto __maybe_unused,
		 const __u64 flags __maybe_unused)
{
	const __s32 len_diff = proto == __constant_htons(ETH_P_IPV6) ?
			       20 /* 4->6 */ : -20 /* 6->4 */;
	const __u32 move_len = 14;
	void *data, *data_end;
	int ret;

	/* We make the assumption that when ctx_change_proto() is called
	 * the target proto != current proto.
	 */
	build_bug_on(flags != 0);
	build_bug_on(proto != __constant_htons(ETH_P_IPV6) &&
		     proto != __constant_htons(ETH_P_IP));

	if (len_diff < 0) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		if (data + move_len + -len_diff <= data_end)
			__bpf_memmove_fwd(data + -len_diff, data, move_len);
		else
			return -EFAULT;
	}
	ret = xdp_adjust_head(ctx, -len_diff);
	if (!ret && len_diff > 0) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		if (data + move_len + len_diff <= data_end)
			__bpf_memmove_fwd(data, data + len_diff, move_len);
		else
			return -EFAULT;
	}
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data_end by <[ delta ]>(IP: 1) bytes. It is only possible to shrink the packet as of this writing , therefore <[ delta ]>(IP: 1) must be a negative integer. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "xdp_adjust_tail",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "xdp_adjust_tail": [
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn ctx",
          " len_diff"
        ]
      }
    ]
  },
  "startLine": 236,
  "endLine": 240,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_adjust_troom",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " const __s32 len_diff"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "xdp_adjust_tail"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_adjust_troom (struct xdp_md *ctx, const __s32 len_diff)\n",
    "{\n",
    "    return xdp_adjust_tail (ctx, len_diff);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
ctx_adjust_troom(struct xdp_md *ctx, const __s32 len_diff)
{
	return xdp_adjust_tail(ctx, len_diff);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "xdp_adjust_head": [
      {
        "opVar": "\tret ",
        "inpVar": [
          " ctx",
          " -len_diff"
        ]
      }
    ]
  },
  "startLine": 242,
  "endLine": 289,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_adjust_hroom",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " const __s32 len_diff",
    " const __u32 mode",
    " const __u64 flags __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_adjust_hroom (struct xdp_md *ctx, const __s32 len_diff, const __u32 mode, const __u64 flags __maybe_unused)\n",
    "{\n",
    "    const __u32 move_len_v4 = 14 + 20;\n",
    "    const __u32 move_len_v6 = 14 + 40;\n",
    "    void *data, *data_end;\n",
    "    int ret;\n",
    "    build_bug_on (len_diff <= 0 || len_diff >= 64);\n",
    "    build_bug_on (mode != BPF_ADJ_ROOM_NET);\n",
    "    ret = xdp_adjust_head (ctx, - len_diff);\n",
    "    if (!ret) {\n",
    "        data_end = ctx_data_end (ctx);\n",
    "        data = ctx_data (ctx);\n",
    "        switch (len_diff) {\n",
    "        case 28 :\n",
    "            break;\n",
    "        case 20 :\n",
    "        case 8 :\n",
    "            if (data + move_len_v4 + len_diff <= data_end)\n",
    "                __bpf_memmove_fwd (data, data + len_diff, move_len_v4);\n",
    "            else\n",
    "                ret = -EFAULT;\n",
    "            break;\n",
    "        case 48 :\n",
    "            break;\n",
    "        case 40 :\n",
    "        case 24 :\n",
    "            if (data + move_len_v6 + len_diff <= data_end)\n",
    "                __bpf_memmove_fwd (data, data + len_diff, move_len_v6);\n",
    "            else\n",
    "                ret = -EFAULT;\n",
    "            break;\n",
    "        default :\n",
    "            __throw_build_bug ();\n",
    "        }\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
ctx_adjust_hroom(struct xdp_md *ctx, const __s32 len_diff, const __u32 mode,
		 const __u64 flags __maybe_unused)
{
	const __u32 move_len_v4 = 14 + 20;
	const __u32 move_len_v6 = 14 + 40;
	void *data, *data_end;
	int ret;

	build_bug_on(len_diff <= 0 || len_diff >= 64);
	build_bug_on(mode != BPF_ADJ_ROOM_NET);

	ret = xdp_adjust_head(ctx, -len_diff);

	/* XXX: Note, this hack is currently tailored to NodePort DSR
	 * requirements and not a generic helper. If needed elsewhere,
	 * this must be made more generic.
	 */
	if (!ret) {
		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);
		switch (len_diff) {
		case 28: /* struct {iphdr + icmphdr} */
			break;
		case 20: /* struct iphdr */
		case 8:  /* __u32 opt[2] */
			if (data + move_len_v4 + len_diff <= data_end)
				__bpf_memmove_fwd(data, data + len_diff,
						  move_len_v4);
			else
				ret = -EFAULT;
			break;
		case 48: /* struct {ipv6hdr + icmp6hdr} */
			break;
		case 40: /* struct ipv6hdr */
		case 24: /* struct dsr_opt_v6 */
			if (data + move_len_v6 + len_diff <= data_end)
				__bpf_memmove_fwd(data, data + len_diff,
						  move_len_v6);
			else
				ret = -EFAULT;
			break;
		default:
			__throw_build_bug();
		}
	}
	return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx_const struct xdp_md *ctx",
          " int ifindex",
          " const __u32 flags"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\treturn ifindex",
          " flags"
        ]
      }
    ]
  },
  "startLine": 291,
  "endLine": 298,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_redirect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx",
    " int ifindex",
    " const __u32 flags"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_redirect (const struct xdp_md *ctx, int ifindex, const __u32 flags)\n",
    "{\n",
    "    if ((__u32) ifindex == ctx->ingress_ifindex)\n",
    "        return XDP_TX;\n",
    "    return redirect (ifindex, flags);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
ctx_redirect(const struct xdp_md *ctx, int ifindex, const __u32 flags)
{
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;

	return redirect(ifindex, flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "redirect": [
      {
        "opVar": "NA",
        "inpVar": [
          "ctx__peerconst struct xdp_md *ctx __maybe_unused",
          "\t\t  int ifindex __maybe_unused",
          "\t\t  const __u32 flags __maybe_unused"
        ]
      }
    ]
  },
  "startLine": 300,
  "endLine": 307,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_redirect_peer",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md * ctx __maybe_unused",
    " int ifindex __maybe_unused",
    " const __u32 flags __maybe_unused"
  ],
  "output": "static__always_inline__maybe_unusedint",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "xdp",
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __maybe_unused int ctx_redirect_peer (const struct xdp_md * ctx __maybe_unused, int ifindex __maybe_unused, const __u32 flags __maybe_unused)\n",
    "{\n",
    "    return -ENOTSUP;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused int
ctx_redirect_peer(const struct xdp_md *ctx __maybe_unused,
		  int ifindex __maybe_unused,
		  const __u32 flags __maybe_unused)
{
	/* bpf_redirect_peer() is available only in TC BPF. */
	return -ENOTSUP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 309,
  "endLine": 314,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_full_len",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u64",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u64 ctx_full_len (const struct xdp_md *ctx)\n",
    "{\n",
    "    return ctx_data_end (ctx) - ctx_data (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused __u64
ctx_full_len(const struct xdp_md *ctx)
{
	/* No non-linear section in XDP. */
	return ctx_data_end(ctx) - ctx_data(ctx);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 316,
  "endLine": 320,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_wire_len",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u32 ctx_wire_len (const struct xdp_md *ctx)\n",
    "{\n",
    "    return ctx_full_len (ctx);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused __u32
ctx_wire_len(const struct xdp_md *ctx)
{
	return ctx_full_len(ctx);
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, META_PIVOT);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} cilium_xdp_scratch __section_maps_btf;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\t__u32 zero ",
        "inpVar": [
          " 0",
          " *data_meta "
        ]
      }
    ]
  },
  "startLine": 330,
  "endLine": 338,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_store_meta",
  "updateMaps": [],
  "readMaps": [
    " cilium_xdp_scratch"
  ],
  "input": [
    "struct xdp_md * ctx __maybe_unused",
    " const __u64 off",
    " __u32 datum"
  ],
  "output": "static__always_inline__maybe_unusedvoid",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused void ctx_store_meta (struct xdp_md * ctx __maybe_unused, const __u64 off, __u32 datum)\n",
    "{\n",
    "    __u32 zero = 0, *data_meta = map_lookup_elem (&cilium_xdp_scratch, &zero);\n",
    "    if (always_succeeds (data_meta))\n",
    "        data_meta[off] = datum;\n",
    "    build_bug_on ((off + 1) * sizeof (__u32) > META_PIVOT);\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused void
ctx_store_meta(struct xdp_md *ctx __maybe_unused, const __u64 off, __u32 datum)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		data_meta[off] = datum;
	build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\t__u32 zero ",
        "inpVar": [
          " 0",
          " *data_meta "
        ]
      }
    ]
  },
  "startLine": 340,
  "endLine": 349,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_load_meta",
  "updateMaps": [],
  "readMaps": [
    " cilium_xdp_scratch"
  ],
  "input": [
    "const struct xdp_md * ctx __maybe_unused",
    " const __u64 off"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u32 ctx_load_meta (const struct xdp_md * ctx __maybe_unused, const __u64 off)\n",
    "{\n",
    "    __u32 zero = 0, *data_meta = map_lookup_elem (&cilium_xdp_scratch, &zero);\n",
    "    if (always_succeeds (data_meta))\n",
    "        return data_meta[off];\n",
    "    build_bug_on ((off + 1) * sizeof (__u32) > META_PIVOT);\n",
    "    return 0;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused __u32
ctx_load_meta(const struct xdp_md *ctx __maybe_unused, const __u64 off)
{
	__u32 zero = 0, *data_meta = map_lookup_elem(&cilium_xdp_scratch, &zero);

	if (always_succeeds(data_meta))
		return data_meta[off];
	build_bug_on((off + 1) * sizeof(__u32) > META_PIVOT);
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 351,
  "endLine": 361,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_get_protocol",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u16",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u16 ctx_get_protocol (const struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = ctx_data_end (ctx);\n",
    "    struct ethhdr *eth = ctx_data (ctx);\n",
    "    if (ctx_no_room (eth + 1, data_end))\n",
    "        return 0;\n",
    "    return eth->h_proto;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused __u16
ctx_get_protocol(const struct xdp_md *ctx)
{
	void *data_end = ctx_data_end(ctx);
	struct ethhdr *eth = ctx_data(ctx);

	if (ctx_no_room(eth + 1, data_end))
		return 0;

	return eth->h_proto;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 363,
  "endLine": 367,
  "File": "/home/sayandes/opened_extraction/examples/cilium/include/bpf/ctx/xdp.h",
  "funcName": "ctx_get_ifindex",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct xdp_md *ctx"
  ],
  "output": "static__always_inline__maybe_unused__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "sk_reuseport",
    "cgroup_sysctl",
    "kprobe",
    "sched_cls",
    "socket_filter",
    "sched_act",
    "lwt_seg6local",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "perf_event",
    "sk_skb",
    "cgroup_skb",
    "sock_ops",
    "tracepoint"
  ],
  "source": [
    "static __always_inline __maybe_unused __u32 ctx_get_ifindex (const struct xdp_md *ctx)\n",
    "{\n",
    "    return ctx->ingress_ifindex;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    null
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
static __always_inline __maybe_unused __u32
ctx_get_ifindex(const struct xdp_md *ctx)
{
	return ctx->ingress_ifindex;
}

#endif /* __BPF_CTX_XDP_H_ */
