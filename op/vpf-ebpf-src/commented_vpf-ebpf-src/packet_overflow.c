// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t _1;
    uint32_t _2;
    uint32_t _3;
};

struct ctx;

__attribute__((section("xdp"), used))
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 27,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/packet_overflow.c",
  "funcName": "read_write_packet_start",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_skb",
    "cgroup_sock_addr",
    "lwt_out",
    "lwt_xmit",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "sk_reuseport",
    "flow_dissector",
    "cgroup_sysctl",
    "sched_act",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_skb",
    "sched_cls",
    "lwt_in",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device",
    "xdp",
    "tracepoint",
    "socket_filter"
  ],
  "source": [
    "int read_write_packet_start (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    if (data > data_end)\n",
    "        return 1;\n",
    "    int value = *(int*) data;\n",
    "    *(int*) data = value + 1;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {}
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
int read_write_packet_start(struct xdp_md* ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data > data_end)
        return 1;
    int value = *(int*)data;
    *(int*)data = value + 1;
    return 0;
}
