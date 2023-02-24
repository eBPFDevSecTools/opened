// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

typedef struct bpf_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;
#define BPF_MAP_TYPE_ARRAY 2

__attribute__((section("maps"), used))
bpf_map_def_t map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(int),
     .value_size = sizeof(uint32_t),
     .max_entries = 1};

static void* (*bpf_map_lookup_elem)(bpf_map_def_t* map, void* key) = (void*) 1;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
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
        "opVar": "    uint64_t* ptr ",
        "inpVar": [
          " &map",
          " &key"
        ]
      }
    ]
  },
  "startLine": 26,
  "endLine": 39,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/mapvalue-overrun.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int func (void *ctx)\n",
    "{\n",
    "    uint32_t key = 1;\n",
    "    uint64_t *ptr = bpf_map_lookup_elem (&map, &key);\n",
    "    if (ptr == 0) {\n",
    "        return 0;\n",
    "    }\n",
    "    uint64_t i = *ptr;\n",
    "    return (uint32_t) i;\n",
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
int func(void* ctx)
{
    uint32_t key = 1;

    uint64_t* ptr = bpf_map_lookup_elem(&map, &key);
    if (ptr == 0) {
        return 0;
    }

    // The map's value size can only hold a uint32_t.
    // So verification should fail if we try to read past the space returned.
    uint64_t i = *ptr;
    return (uint32_t)i;
}
