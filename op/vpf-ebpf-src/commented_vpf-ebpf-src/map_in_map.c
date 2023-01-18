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
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12

static void* (*bpf_map_lookup_elem)(struct ebpf_map* map, const void* key) = (void*) 1;

__attribute__((section("maps"), used))
struct ebpf_map array_of_maps =
    {.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
     .key_size = sizeof(uint32_t),
     .value_size = sizeof(uint32_t),
     .max_entries = 1,
     .inner_map_idx = 1}; // (uint32_t)&inner_map};

__attribute__((section("maps"), used))
struct ebpf_map inner_map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(uint32_t),
     .value_size = sizeof(uint64_t),
     .max_entries = 1};


/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
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
        "opVar": "    void* nolocal_lru_map ",
        "inpVar": [
          " &array_of_maps",
          " &outer_key"
        ]
      },
      {
        "opVar": "        void* ret ",
        "inpVar": [
          " nolocal_lru_map",
          " &inner_key"
        ]
      },
      {
        "opVar": "            ret ",
        "inpVar": [
          " &inner_map",
          " &inner_key"
        ]
      }
    ]
  },
  "startLine": 35,
  "endLine": 49,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/map_in_map.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [
    " nolocal_lru_map",
    " array_of_maps",
    "  inner_map"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sk_msg",
    "raw_tracepoint_writable",
    "sched_cls",
    "kprobe",
    "cgroup_skb",
    "tracepoint",
    "lwt_xmit",
    "sched_act",
    "cgroup_sysctl",
    "xdp",
    "sk_skb",
    "perf_event",
    "flow_dissector",
    "sock_ops",
    "cgroup_sock",
    "lwt_out",
    "socket_filter",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_device"
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
int func(void* ctx) {
    uint32_t outer_key = 0;
    void* nolocal_lru_map = bpf_map_lookup_elem(&array_of_maps, &outer_key);
    if (nolocal_lru_map) {
        uint32_t inner_key = 0;
        void* ret = bpf_map_lookup_elem(nolocal_lru_map, &inner_key);
        if (ret) {
            return 0;
        } else {
            ret = bpf_map_lookup_elem(&inner_map, &inner_key);
            return 0;
        }
    }
    return 0;
}
