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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_prandom_u32": [
      {
        "opVar": "    uint32_t rand32 ",
        "inpVar": [
          " "
        ]
      },
      {
        "opVar": "            stack_buffer[i] ",
        "inpVar": [
          " "
        ]
      },
      {
        "opVar": "            stack_buffer2[i] ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
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
    "xdp",
    "tracepoint",
    "perf_event",
    "lwt_seg6local",
    "lwt_out",
    "cgroup_skb",
    "lwt_in",
    "cgroup_sock_addr",
    "sk_skb",
    "flow_dissector",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "sk_msg",
    "sched_act",
    "sk_reuseport",
    "kprobe",
    "sock_ops",
    "sched_cls",
    "socket_filter",
    "cgroup_sock",
    "lwt_xmit"
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
