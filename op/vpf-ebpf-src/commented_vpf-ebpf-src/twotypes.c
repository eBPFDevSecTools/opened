// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

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
     .value_size = 1024,
     .max_entries = 1};

static void* (*bpf_map_lookup_elem)(struct ebpf_map* map, const void* key) = (void*) 1;
static int (*get_prandom_u32)() = (void*)7;

struct ctx;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
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
        "opVar": "    uint8_t* map_value ",
        "inpVar": [
          " uint8_t*&map",
          " &map_key"
        ]
      }
    ]
  },
  "startLine": 29,
  "endLine": 48,
  "File": "/home/palani/github/opened_extraction/examples/vpf-ebpf-src/twotypes.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "cgroup_skb",
    "sk_skb",
    "xdp",
    "cgroup_device",
    "raw_tracepoint_writable",
    "socket_filter",
    "kprobe",
    "raw_tracepoint",
    "lwt_seg6local",
    "lwt_xmit",
    "tracepoint",
    "sk_msg",
    "lwt_in",
    "sk_reuseport",
    "sock_ops",
    "cgroup_sock",
    "perf_event",
    "sched_cls",
    "flow_dissector",
    "cgroup_sock_addr",
    "sched_act",
    "lwt_out"
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
int func(struct ctx* ctx)
{
    uint32_t rand32 = get_prandom_u32();
    uint8_t stack_buffer[256] = { 0 };
    *(uint32_t*)stack_buffer = rand32;

    int map_key = 0;
    uint8_t* map_value = (uint8_t*)bpf_map_lookup_elem(&map, &map_key);
    if (map_value == 0)
        return 0;

    uint8_t* ptr;
    if (rand32 & 1) {
        ptr = map_value;
    } else {
        ptr = stack_buffer + 128;
    }

    return (*ptr == stack_buffer[0]) ? 1 : 0;
}
