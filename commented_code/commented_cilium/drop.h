/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Drop & error notification via perf event ring buffer
 *
 * API:
 * int send_drop_notify(ctx, src, dst, dst_id, reason, exitcode, enum metric_dir direction)
 * int send_drop_notify_error(ctx, error, exitcode, enum metric_dir direction)
 *
 * If DROP_NOTIFY is not defined, the API will be compiled in as a NOP.
 */

#ifndef __LIB_DROP__
#define __LIB_DROP__

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"

#ifdef DROP_NOTIFY
struct drop_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u32		dst_id;
	__u16		line;
	__u8		file;
	__s8		ext_error;
};

/*
 * We pass information in the meta area as follows:
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Source Label                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       Destination Label                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  Error Code  | Extended Error|            Unused              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |             Designated Destination Endpoint ID                |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |   Exit Code  |  Source File  |         Source Line            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_DROP_NOTIFY)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 52,
  "endLine": 80,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/drop.h",
  "funcName": "__send_drop_notify",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx"
  ],
  "output": "int",
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
    "int __send_drop_notify (struct  __ctx_buff *ctx)\n",
    "{\n",
    "    __u32 error = ctx_load_meta (ctx, 2) & 0xFFFFFFFF;\n",
    "    __u64 ctx_len = ctx_full_len (ctx);\n",
    "    __u64 cap_len = min_t (__u64, TRACE_PAYLOAD_LEN, ctx_len);\n",
    "    __u32 meta4 = ctx_load_meta (ctx, 4);\n",
    "    __u16 line = (__u16) (meta4 >> 16);\n",
    "    __u8 file = (__u8) (meta4 >> 8);\n",
    "    __u8 exitcode = (__u8) meta4;\n",
    "    struct drop_notify msg;\n",
    "    msg = (typeof (msg)) {__notify_common_hdr (CILIUM_NOTIFY_DROP, (__u8) error), __notify_pktcap_hdr (ctx_len, (__u16) cap_len),\n",
    "        .src_label = ctx_load_meta (ctx, 0),\n",
    "        .dst_label = ctx_load_meta (ctx, 1),\n",
    "        .dst_id = ctx_load_meta (ctx, 3),\n",
    "        .line = line,\n",
    "        .file = file,\n",
    "        .ext_error = (__s8) (__u8) (error >> 8),};\n",
    "    ctx_event_output (ctx, &EVENTS_MAP, (cap_len << 32) | BPF_F_CURRENT_CPU, &msg, sizeof (msg));\n",
    "    return exitcode;\n",
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
int __send_drop_notify(struct __ctx_buff *ctx)
{
	/* Mask needed to calm verifier. */
	__u32 error = ctx_load_meta(ctx, 2) & 0xFFFFFFFF;
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	__u32 meta4 = ctx_load_meta(ctx, 4);
	__u16 line = (__u16)(meta4 >> 16);
	__u8 file = (__u8)(meta4 >> 8);
	__u8 exitcode = (__u8)meta4;
	struct drop_notify msg;

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_DROP, (__u8)error),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= ctx_load_meta(ctx, 0),
		.dst_label	= ctx_load_meta(ctx, 1),
		.dst_id		= ctx_load_meta(ctx, 3),
		.line           = line,
		.file           = file,
		.ext_error      = (__s8)(__u8)(error >> 8),
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));

	return exitcode;
}

/**
 * send_drop_notify
 * @ctx:	socket buffer
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	designated destination endpoint ID
 * @reason:	Reason for drop
 * @exitcode:	error code to return to the kernel
 *
 * Generate a notification to indicate a packet was dropped.
 *
 * NOTE: This is terminal function and will cause the BPF program to exit
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tep_ctx",
          " CILIUM_CALL_DROP_NOTIFY"
        ]
      }
    ]
  },
  "startLine": 95,
  "endLine": 116,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/drop.h",
  "funcName": "_send_drop_notify",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 file",
    " __u16 line",
    " struct  __ctx_buff *ctx",
    " __u32 src",
    " __u32 dst",
    " __u32 dst_id",
    " __u32 reason",
    " __u32 exitcode",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "tail_call"
  ],
  "compatibleHookpoints": [
    "cgroup_sock_addr",
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_out",
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
    "static __always_inline int _send_drop_notify (__u8 file, __u16 line, struct  __ctx_buff *ctx, __u32 src, __u32 dst, __u32 dst_id, __u32 reason, __u32 exitcode, enum metric_dir direction)\n",
    "{\n",
    "    if (!__builtin_constant_p (exitcode) || exitcode > 0xff || !__builtin_constant_p (file) || file > 0xff || !__builtin_constant_p (line) || line > 0xffff)\n",
    "        __throw_build_bug ();\n",
    "    ctx_store_meta (ctx, 0, src);\n",
    "    ctx_store_meta (ctx, 1, dst);\n",
    "    ctx_store_meta (ctx, 2, reason);\n",
    "    ctx_store_meta (ctx, 3, dst_id);\n",
    "    ctx_store_meta (ctx, 4, exitcode | file << 8 | line << 16);\n",
    "    update_metrics (ctx_full_len (ctx), direction, (__u8) reason);\n",
    "    ep_tail_call (ctx, CILIUM_CALL_DROP_NOTIFY);\n",
    "    return exitcode;\n",
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
static __always_inline int
_send_drop_notify(__u8 file, __u16 line, struct __ctx_buff *ctx,
		  __u32 src, __u32 dst, __u32 dst_id,
		  __u32 reason, __u32 exitcode, enum metric_dir direction)
{
	/* These fields should be constants and fit (together) in 32 bits */
	if (!__builtin_constant_p(exitcode) || exitcode > 0xff ||
	    !__builtin_constant_p(file) || file > 0xff ||
	    !__builtin_constant_p(line) || line > 0xffff)
		__throw_build_bug();

	ctx_store_meta(ctx, 0, src);
	ctx_store_meta(ctx, 1, dst);
	ctx_store_meta(ctx, 2, reason);
	ctx_store_meta(ctx, 3, dst_id);
	ctx_store_meta(ctx, 4, exitcode | file << 8 | line << 16);

	update_metrics(ctx_full_len(ctx), direction, (__u8)reason);
	ep_tail_call(ctx, CILIUM_CALL_DROP_NOTIFY);

	return exitcode;
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 118,
  "endLine": 126,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/drop.h",
  "funcName": "_send_drop_notify",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u8 file __maybe_unused",
    " __u16 line __maybe_unused",
    " struct  __ctx_buff *ctx",
    " __u32 src __maybe_unused",
    " __u32 dst __maybe_unused",
    " __u32 dst_id __maybe_unused",
    " __u32 reason",
    " __u32 exitcode",
    " enum metric_dir direction"
  ],
  "output": "static__always_inlineint",
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
    "static __always_inline int _send_drop_notify (__u8 file __maybe_unused, __u16 line __maybe_unused, struct  __ctx_buff *ctx, __u32 src __maybe_unused, __u32 dst __maybe_unused, __u32 dst_id __maybe_unused, __u32 reason, __u32 exitcode, enum metric_dir direction)\n",
    "{\n",
    "    update_metrics (ctx_full_len (ctx), direction, (__u8) reason);\n",
    "    return exitcode;\n",
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
static __always_inline
int _send_drop_notify(__u8 file __maybe_unused, __u16 line __maybe_unused,
		      struct __ctx_buff *ctx, __u32 src __maybe_unused,
		      __u32 dst __maybe_unused, __u32 dst_id __maybe_unused,
		      __u32 reason, __u32 exitcode, enum metric_dir direction)
{
	update_metrics(ctx_full_len(ctx), direction, (__u8)reason);
	return exitcode;
}
#endif /* DROP_NOTIFY */

/*
 * The following macros are required in order to pass source file/line
 * information. The *_ext versions take an additional parameter ext_err
 * which can be used to pass additional information, e.g., this could be an
 * original error returned by fib_lookup (if reason == DROP_NO_FIB).
 */

#ifndef __MAGIC_FILE__
#define __MAGIC_FILE__ 0
#endif

/*
 * Cilium errors are greater than absolute errno values, so we just pass
 * a positive value here
 */
#define __DROP_REASON(err) ({ \
	typeof(err) __err = (err); \
	(__u8)(__err > 0 ? __err : -__err); \
})

/*
 * We only have 8 bits here to pass either a small positive value or an errno
 * (this can be fixed by changing the layout of struct drop_notify, but for now
 * we can hack this as follows). So we pass a negative errno value as is if it
 * is >= -128, and set it 0 if it is < -128 (which actually shoudn't happen in
 * our case)
 */
#define __DROP_REASON_EXT(err, ext_err) ({ \
	typeof(ext_err) __ext_err = (ext_err); \
	__DROP_REASON(err) | ((__u8)(__ext_err < -128 ? 0 : __ext_err) << 8); \
})

#define send_drop_notify(ctx, src, dst, dst_id, reason, exitcode, direction) \
	_send_drop_notify(__MAGIC_FILE__, __LINE__, ctx, src, dst, dst_id, \
			  __DROP_REASON(reason), exitcode, direction)

#define send_drop_notify_error(ctx, src, reason, exitcode, direction) \
	_send_drop_notify(__MAGIC_FILE__, __LINE__, ctx, src, 0, 0, \
			  __DROP_REASON(reason), exitcode, direction)

#define send_drop_notify_ext(ctx, src, dst, dst_id, reason, ext_err, exitcode, direction) \
	_send_drop_notify(__MAGIC_FILE__, __LINE__, ctx, src, dst, dst_id, \
			  __DROP_REASON_EXT(reason, ext_err), exitcode, direction)

#define send_drop_notify_error_ext(ctx, src, reason, ext_err, exitcode, direction) \
	_send_drop_notify(__MAGIC_FILE__, __LINE__, ctx, src, 0, 0, \
			  __DROP_REASON_EXT(reason, ext_err), exitcode, direction)

#endif /* __LIB_DROP__ */