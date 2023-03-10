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
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/packet_start_ok.c",
  "funcName": "read_write_packet_start",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_sysctl",
    "lwt_in",
    "sk_msg",
    "perf_event",
    "cgroup_skb",
    "lwt_xmit",
    "sk_skb",
    "socket_filter",
    "cgroup_sock",
    "sched_act",
    "flow_dissector",
    "tracepoint",
    "cgroup_device",
    "sock_ops",
    "raw_tracepoint",
    "lwt_seg6local",
    "xdp",
    "sched_cls",
    "lwt_out",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock_addr"
  ],
  "source": [
    "int read_write_packet_start (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    if (data + sizeof (int) > data_end)\n",
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
    if (data + sizeof(int) > data_end)
        return 1;
    int value = *(int*)data;
    *(int*)data = value + 1;
    return 0;
}
