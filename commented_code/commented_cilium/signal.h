/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_SIGNAL_H_
#define __LIB_SIGNAL_H_

#include <bpf/api.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, __NR_CPUS__);
} SIGNAL_MAP __section_maps_btf;

enum {
	SIGNAL_NAT_FILL_UP = 0,
	SIGNAL_CT_FILL_UP,
};

enum {
	SIGNAL_PROTO_V4 = 0,
	SIGNAL_PROTO_V6,
};

struct signal_msg {
	__u32 signal_nr;
	union {
		struct {
			__u32 proto;
		};
	};
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 36,
  "endLine": 41,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/signal.h",
  "funcName": "send_signal",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " struct signal_msg *msg"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "send_signal"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "kprobe",
    "perf_event",
    "raw_tracepoint_writable",
    "tracepoint"
  ],
  "source": [
    "static __always_inline void send_signal (struct  __ctx_buff *ctx, struct signal_msg *msg)\n",
    "{\n",
    "    ctx_event_output (ctx, &SIGNAL_MAP, BPF_F_CURRENT_CPU, msg, sizeof (*msg));\n",
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
static __always_inline void send_signal(struct __ctx_buff *ctx,
					struct signal_msg *msg)
{
	ctx_event_output(ctx, &SIGNAL_MAP, BPF_F_CURRENT_CPU,
			 msg, sizeof(*msg));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "send_signal": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tctx",
          " &msg"
        ]
      }
    ]
  },
  "startLine": 43,
  "endLine": 52,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/signal.h",
  "funcName": "send_signal_nat_fill_up",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 proto"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "send_signal"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "kprobe",
    "perf_event",
    "raw_tracepoint_writable",
    "tracepoint"
  ],
  "source": [
    "static __always_inline void send_signal_nat_fill_up (struct  __ctx_buff *ctx, __u32 proto)\n",
    "{\n",
    "    struct signal_msg msg = {\n",
    "        .signal_nr = SIGNAL_NAT_FILL_UP,\n",
    "        .proto = proto,}\n",
    "    ;\n",
    "    send_signal (ctx, &msg);\n",
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
static __always_inline void send_signal_nat_fill_up(struct __ctx_buff *ctx,
						    __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_NAT_FILL_UP,
		.proto		= proto,
	};

	send_signal(ctx, &msg);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "send_signal": [
      {
        "opVar": "NA",
        "inpVar": [
          "\tctx",
          " &msg"
        ]
      }
    ]
  },
  "startLine": 54,
  "endLine": 63,
  "File": "/home/sayandes/opened_extraction/examples/cilium/lib/signal.h",
  "funcName": "send_signal_ct_fill_up",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u32 proto"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "send_signal"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "kprobe",
    "perf_event",
    "raw_tracepoint_writable",
    "tracepoint"
  ],
  "source": [
    "static __always_inline void send_signal_ct_fill_up (struct  __ctx_buff *ctx, __u32 proto)\n",
    "{\n",
    "    struct signal_msg msg = {\n",
    "        .signal_nr = SIGNAL_CT_FILL_UP,\n",
    "        .proto = proto,}\n",
    "    ;\n",
    "    send_signal (ctx, &msg);\n",
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
static __always_inline void send_signal_ct_fill_up(struct __ctx_buff *ctx,
						   __u32 proto)
{
	struct signal_msg msg = {
		.signal_nr	= SIGNAL_CT_FILL_UP,
		.proto		= proto,
	};

	send_signal(ctx, &msg);
}

#endif /* __LIB_SIGNAL_H_ */
