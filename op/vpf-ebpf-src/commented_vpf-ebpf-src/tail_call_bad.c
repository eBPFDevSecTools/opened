// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;

#define BPF_MAP_TYPE_ARRAY 2

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
    BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "        long error ",
        "inpVar": [
          " ctx",
          " &map",
          " 0"
        ]
      }
    ]
  },
  "startLine": 24,
  "endLine": 32,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/tail_call_bad.c",
  "funcName": "caller",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "cgroup_sock",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sched_act",
    "sched_cls",
    "sk_skb",
    "xdp",
    "sock_ops",
    "lwt_out",
    "lwt_xmit",
    "tracepoint",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_skb",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "socket_filter"
  ],
  "source": [
    "int caller (struct xdp_md *ctx)\n",
    "{\n",
    "    long error = bpf_tail_call (ctx, & map, 0);\n",
    "    return (int) error;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
    // This should fail validation since the map is not a prog array.
    long error = bpf_tail_call(ctx, &map, 0);

    // bpf_tail_call failed at runtime.
    return (int)error;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 34,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/tail_call_bad.c",
  "funcName": "callee",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "cgroup_sock",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sched_act",
    "sched_cls",
    "sk_skb",
    "xdp",
    "sock_ops",
    "lwt_out",
    "cgroup_sysctl",
    "lwt_xmit",
    "tracepoint",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device",
    "cgroup_skb",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "socket_filter"
  ],
  "source": [
    "int callee (struct xdp_md *ctx)\n",
    "{\n",
    "    return 42;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
