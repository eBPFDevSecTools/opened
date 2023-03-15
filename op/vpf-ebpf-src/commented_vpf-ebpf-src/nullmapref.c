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
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/nullmapref.c",
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
      "text": "// ebpf_map_lookup_elem can return NULL if not found,"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "// so this unchecked dereference should fail verification."
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " test_map"
  ],
  "input": [
    "void *ctx"
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
    "int test_repro (void *ctx)\n",
    "{\n",
    "    uint32_t key = 1;\n",
    "    uint32_t *value = ebpf_map_lookup_elem (&test_map, &key);\n",
    "    *value = 1;\n",
    "    return 0;\n",
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

    uint32_t* value = ebpf_map_lookup_elem(&test_map, &key);

    // ebpf_map_lookup_elem can return NULL if not found,
    // so this unchecked dereference should fail verification.
    *value = 1;

    return 0;
}
