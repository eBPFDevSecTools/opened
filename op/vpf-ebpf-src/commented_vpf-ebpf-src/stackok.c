// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

static int (*get_prandom_u32)() = (void*)7;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 19,
  "File": "/home/palani/github/opened_extraction/examples/vpf-ebpf-src/stackok.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [],
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
