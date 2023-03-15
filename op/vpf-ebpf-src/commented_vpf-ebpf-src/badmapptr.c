// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

typedef unsigned int uint32_t;

typedef struct _bpf_map_def
{
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;

typedef void* (*ebpf_map_lookup_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_lookup_elem ((ebpf_map_lookup_elem_t)1)

#pragma clang section data = "maps"
bpf_map_def_t test_map = {
    .type = 1, // BPF_MAP_TYPE_HASH
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

#pragma clang section text = "test"
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 28,
  "endLine": 40,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/badmapptr.c",
  "funcName": "test_repro",
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
      "start_line": 22,
      "end_line": 22,
      "text": "// BPF_MAP_TYPE_HASH"
    },
    {
      "start_line": 35,
      "end_line": 35,
      "text": "// Instead of passing in the correct map pointer, pass in a value past it."
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "// This should fail verification."
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " map + 1"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "flow_dissector",
    "sched_act",
    "cgroup_device",
    "lwt_in",
    "sk_skb",
    "sk_reuseport",
    "sched_cls",
    "tracepoint",
    "lwt_xmit",
    "cgroup_skb",
    "sock_ops",
    "kprobe",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "cgroup_sysctl",
    "cgroup_sock",
    "perf_event",
    "raw_tracepoint_writable",
    "lwt_out",
    "raw_tracepoint",
    "sk_msg",
    "socket_filter",
    "xdp"
  ],
  "source": [
    "int test_repro (void *ctx)\n",
    "{\n",
    "    uint32_t key = 1;\n",
    "    bpf_map_def_t *map = &test_map;\n",
    "    uint32_t *value = ebpf_map_lookup_elem (map + 1, &key);\n",
    "    return (value != 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "ebpf_map_lookup_elem"
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
int
test_repro(void* ctx)
{
    uint32_t key = 1;

    bpf_map_def_t* map = &test_map;

    // Instead of passing in the correct map pointer, pass in a value past it.
    // This should fail verification.
    uint32_t* value = ebpf_map_lookup_elem(map + 1, &key);

    return (value != 0);
}
