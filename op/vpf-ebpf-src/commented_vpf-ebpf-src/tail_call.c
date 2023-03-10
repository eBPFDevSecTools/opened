// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;

#define BPF_MAP_TYPE_PROG_ARRAY 3

typedef struct bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;

struct xdp_md;

static long (*bpf_tail_call)(void *ctx, struct bpf_map *prog_array_map, uint32_t index) = (void*) 12;

__attribute__((section("maps"), used)) struct bpf_map map = {
    BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 31,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/tail_call.c",
  "funcName": "caller",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_tail_call",
    "tail_call"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "lwt_in",
    "sk_msg",
    "perf_event",
    "cgroup_skb",
    "lwt_xmit",
    "sk_skb",
    "cgroup_sock",
    "socket_filter",
    "sched_act",
    "flow_dissector",
    "tracepoint",
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
    "int caller (struct xdp_md *ctx)\n",
    "{\n",
    "    long error = bpf_tail_call (ctx, & map, 0);\n",
    "    return (int) error;\n",
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
__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    long error = bpf_tail_call(ctx, &map, 0);

    // bpf_tail_call failed at runtime.
    return (int)error;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 33,
  "endLine": 37,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/tail_call.c",
  "funcName": "callee",
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
    "int callee (struct xdp_md *ctx)\n",
    "{\n",
    "    return 42;\n",
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
__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
