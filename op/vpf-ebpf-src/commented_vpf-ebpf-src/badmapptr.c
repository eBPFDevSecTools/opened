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
