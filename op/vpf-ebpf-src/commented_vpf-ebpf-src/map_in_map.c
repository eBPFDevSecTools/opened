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
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "cilium",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 35,
  "endLine": 49,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/map_in_map.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [
    "  inner_map",
    " array_of_maps",
    " nolocal_lru_map"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "map_lookup_elem",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "cgroup_sysctl",
    "lwt_in",
    "sk_msg",
    "perf_event",
    "cgroup_skb",
    "lwt_xmit",
    "sk_skb",
    "cgroup_sock",
    "socket_filter",
    "sched_act",
    "flow_dissector",
    "tracepoint",
    "cgroup_device",
    "sock_ops",
    "raw_tracepoint",
    "lwt_seg6local",
    "xdp",
    "sched_cls",
    "lwt_out",
    "kprobe",
    "raw_tracepoint_writable",
    "cgroup_sock_addr"
  ],
  "source": [
    "int func (void *ctx)\n",
    "{\n",
    "    uint32_t outer_key = 0;\n",
    "    void *nolocal_lru_map = bpf_map_lookup_elem (&array_of_maps, &outer_key);\n",
    "    if (nolocal_lru_map) {\n",
    "        uint32_t inner_key = 0;\n",
    "        void *ret = bpf_map_lookup_elem (nolocal_lru_map, &inner_key);\n",
    "        if (ret) {\n",
    "            return 0;\n",
    "        }\n",
    "        else {\n",
    "            ret = bpf_map_lookup_elem (& inner_map, & inner_key);\n",
    "            return 0;\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
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
