// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct ebpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};
#define BPF_MAP_TYPE_ARRAY 2

__attribute__((section("maps"), used))
struct ebpf_map map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(int),
     .value_size = sizeof(uint64_t),
     .max_entries = 1};

static int (*ebpf_map_update_elem)(struct ebpf_map* map, const void* key,
                                   const void* value, uint64_t flags) = (void*) 2;

struct ctx;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 29,
  "endLine": 36,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/exposeptr.c",
  "funcName": "func",
  "updateMaps": [
    " map"
  ],
  "readMaps": [],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sock",
    "tracepoint",
    "kprobe",
    "sk_msg",
    "flow_dissector",
    "lwt_seg6local",
    "sk_reuseport",
    "sched_cls",
    "lwt_out",
    "lwt_xmit",
    "raw_tracepoint",
    "sock_ops",
    "raw_tracepoint_writable",
    "socket_filter",
    "perf_event",
    "sched_act",
    "lwt_in",
    "sk_skb",
    "cgroup_device",
    "cgroup_sysctl",
    "xdp"
  ],
  "source": [
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    uint32_t key = 0;\n",
    "    return ebpf_map_update_elem (&map, &key, &ctx, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ebpf_map_update_elem",
    "ebpf_get_current_comm"
  ],
  "call_depth": -1,
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
int func(struct ctx* ctx)
{
    uint32_t key = 0;

    // The following should fail verification since it stores
    // a pointer in shared memory, thus exposing it to user-mode apps.
    return ebpf_map_update_elem(&map, &key, &ctx, 0);
}
