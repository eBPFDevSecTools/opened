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
  "endLine": 37,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/mapoverflow.c",
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
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    uint32_t key = 10;\n",
    "    uint64_t value = 0;\n",
    "    return ebpf_map_update_elem (&map, &key, &value, 0);\n",
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
    uint32_t key = 10;
    uint64_t value = 0;

    // The following should fail verification since it tries to
    // write past the size of the array.
    return ebpf_map_update_elem(&map, &key, &value, 0);
}
