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
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "cilium",
          "Return Type": "u32",
          "Description": "Get a pseudo-random number. From a security point of view , this helper uses its own pseudo-random internal state , and cannot be used to infer the seed of other random functions in the kernel. However , it is essential to note that the generator used by the helper is not cryptographically secure. ",
          "Return": " A random 32-bit unsigned value.",
          "Function Name": "get_prandom_u32",
          "Input Params": [
            "{Type: voi ,Var: void}"
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
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 29,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/twotypes.c",
  "funcName": "func",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " map"
  ],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem",
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "cgroup_skb",
    "lwt_in",
    "kprobe",
    "xdp",
    "cgroup_sock",
    "perf_event",
    "tracepoint",
    "sk_reuseport",
    "cgroup_sock_addr",
    "sock_ops",
    "raw_tracepoint_writable",
    "lwt_out",
    "sched_act",
    "lwt_seg6local",
    "sk_msg",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "raw_tracepoint",
    "sk_skb"
  ],
  "source": [
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    uint32_t rand32 = get_prandom_u32 ();\n",
    "    uint8_t stack_buffer [256] = {0};\n",
    "    *(uint32_t*) stack_buffer = rand32;\n",
    "    int map_key = 0;\n",
    "    uint8_t *map_value = (uint8_t *) bpf_map_lookup_elem (&map, &map_key);\n",
    "    if (map_value == 0)\n",
    "        return 0;\n",
    "    uint8_t *ptr;\n",
    "    if (rand32 & 1) {\n",
    "        ptr = map_value;\n",
    "    }\n",
    "    else {\n",
    "        ptr = stack_buffer + 128;\n",
    "    }\n",
    "    return (*ptr == stack_buffer[0]) ? 1 : 0;\n",
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
