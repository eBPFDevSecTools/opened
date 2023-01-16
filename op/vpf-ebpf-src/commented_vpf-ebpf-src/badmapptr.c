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
  "capability": [
    {
      "map_read": [
        {
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": "Map value associated to key, or NULL if no entry was found.",
          "Return Type": "void",
          "Function Name": "*bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "            uint32_t* value ",
        "inpVar": [
          " emap + 1",
          " &key"
        ]
      }
    ]
  },
  "startLine": 28,
  "endLine": 40,
  "File": "/root/examples/vpf-ebpf-src/badmapptr.c",
  "funcName": "test_repro",
  "updateMaps": [],
  "readMaps": [
    " map + 1"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "perf_event",
    "cgroup_sock_addr",
    "socket_filter",
    "cgroup_sock",
    "flow_dissector",
    "lwt_xmit",
    "lwt_out",
    "sched_cls",
    "lwt_seg6local",
    "lwt_in",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint",
    "sk_skb",
    "sk_msg",
    "raw_tracepoint_writable",
    "cgroup_skb",
    "cgroup_device",
    "kprobe",
    "sched_act",
    "cgroup_sysctl",
    "sk_reuseport",
    "xdp"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
