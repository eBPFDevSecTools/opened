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
#define BPF_MAP_TYPE_HASH 1

__attribute__((section("maps"), used))
struct ebpf_map map =
    {.type = BPF_MAP_TYPE_HASH,
     .key_size = sizeof(uint64_t),
     .value_size = sizeof(uint32_t),
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
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/exposeptr2.c",
  "funcName": "func",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// Copyright (c) Prevail Verifier contributors."
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "// SPDX-License-Identifier: MIT"
    },
    {
      "start_line": 33,
      "end_line": 33,
      "text": "// The following should fail verification since it stores"
    },
    {
      "start_line": 34,
      "end_line": 34,
      "text": "// a pointer in shared memory, thus exposing it to user-mode apps."
    }
  ],
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
    "xdp",
    "lwt_seg6local",
    "socket_filter",
    "sk_reuseport",
    "kprobe",
    "raw_tracepoint_writable",
    "lwt_in",
    "sock_ops",
    "tracepoint",
    "sk_skb",
    "cgroup_device",
    "cgroup_sock",
    "sched_cls",
    "lwt_xmit",
    "flow_dissector",
    "raw_tracepoint",
    "sk_msg",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "lwt_out",
    "sched_act",
    "cgroup_skb",
    "perf_event"
  ],
  "source": [
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    uint32_t value = 0;\n",
    "    return ebpf_map_update_elem (&map, &ctx, &value, 0);\n",
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
    uint32_t value = 0;

    // The following should fail verification since it stores
    // a pointer in shared memory, thus exposing it to user-mode apps.
    return ebpf_map_update_elem(&map, &ctx, &value, 0);
}
