// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

static int (*get_prandom_u32)() = (void*)7;

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
  "startLine": 8,
  "endLine": 19,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/stackok.c",
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
      "start_line": 10,
      "end_line": 10,
      "text": "// Initialize an array of 256 bytes (to all zeroes in this example)."
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": "// Set index to a random value in the interval [0,255]."
    },
    {
      "start_line": 17,
      "end_line": 17,
      "text": "// Return the array element at the specified index."
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "flow_dissector",
    "sched_act",
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
    "int func (void *ctx)\n",
    "{\n",
    "    char array [256] = \"\";\n",
    "    uint32_t rand32 = get_prandom_u32 ();\n",
    "    uint32_t index = *(unsignedchar*) &rand32;\n",
    "    return array[index];\n",
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
int func(void* ctx)
{
   // Initialize an array of 256 bytes (to all zeroes in this example).
   char array[256] = "";

   // Set index to a random value in the interval [0,255].
   uint32_t rand32 = get_prandom_u32();
   uint32_t index = *(unsigned char*)&rand32;

   // Return the array element at the specified index.
   return array[index];
}
