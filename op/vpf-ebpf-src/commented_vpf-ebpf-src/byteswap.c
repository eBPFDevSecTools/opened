// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_prandom_u32": [
      {
        "opVar": "   int rand32 ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 8,
  "endLine": 26,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/byteswap.c",
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
    "perf_event",
    "sched_cls",
    "sched_act",
    "socket_filter",
    "lwt_seg6local",
    "sk_reuseport",
    "lwt_xmit",
    "kprobe",
    "lwt_in",
    "xdp",
    "cgroup_sock_addr",
    "sk_msg",
    "cgroup_skb",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "raw_tracepoint_writable",
    "flow_dissector",
    "lwt_out",
    "sock_ops",
    "raw_tracepoint"
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
   int rand32 = get_prandom_u32();

    if (rand32 & 0x01) {
        asm volatile("r0 = le64 r0\nexit");
    } else if (rand32 & 0x02) {
        asm volatile("r0 = le32 r0\nexit");
    } else if (rand32 & 0x04) {
        asm volatile("r0 = le16 r0\nexit");
    } else if (rand32 & 0x10) {
        asm volatile("r0 = be64 r0\nexit");
    } else if (rand32 & 0x20) {
        asm volatile("r0 = be32 r0\nexit");
    } else {
        asm volatile("r0 = be16 r0\nexit");
    }
    return 0;
}
