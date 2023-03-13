// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

struct ctx;

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
  "startLine": 10,
  "endLine": 46,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/twostackvars.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "lwt_xmit",
    "xdp",
    "perf_event",
    "kprobe",
    "lwt_in",
    "sk_skb",
    "sk_reuseport",
    "socket_filter",
    "sched_cls",
    "raw_tracepoint_writable",
    "cgroup_sock_addr",
    "cgroup_sock",
    "lwt_out",
    "tracepoint",
    "flow_dissector",
    "cgroup_skb",
    "sock_ops",
    "sched_act"
  ],
  "source": [
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    int stack_buffer [16];\n",
    "    int *ptr = (int *) 0;\n",
    "    uint32_t rand32 = get_prandom_u32 ();\n",
    "    if (rand32 & 1) {\n",
    "        for (int i = 0; i < 8; i++) {\n",
    "            stack_buffer[i] = get_prandom_u32 ();\n",
    "        }\n",
    "        int index = rand32 % 8;\n",
    "        ptr = &stack_buffer[index];\n",
    "        ptr[index ^ 1] = 0;\n",
    "    }\n",
    "    else {\n",
    "        int *stack_buffer2 = &stack_buffer[8];\n",
    "        for (int i = 0; i < 8; i++) {\n",
    "            stack_buffer2[i] = get_prandom_u32 ();\n",
    "        }\n",
    "        ptr = &stack_buffer2[rand32 % 8];\n",
    "    }\n",
    "    return *ptr;\n",
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
    int stack_buffer[16];
    int *ptr = (int*)0;

    uint32_t rand32 = get_prandom_u32();
    if (rand32 & 1) {
        // In this path we want ptr to point to one section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        for (int i = 0; i < 8; i++) {
            stack_buffer[i] = get_prandom_u32();
        }
        int index = rand32 % 8;
        ptr = &stack_buffer[index];

        // Do something with the pointer to force it to be saved in a
        // register before joining the two paths.
        ptr[index ^ 1] = 0;
    } else {
        // In this path we want ptr to point to a different section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        int* stack_buffer2 = &stack_buffer[8];
        for (int i = 0; i < 8; i++) {
            stack_buffer2[i] = get_prandom_u32();
        }
        ptr = &stack_buffer2[rand32 % 8];
    }

    // Here we want to dereference the pointer to get a number.
    // In both paths above, ptr safely points to a number, even
    // though each part of stack_buffer is not necessarily a number
    // at this point.

    return *ptr;
}
