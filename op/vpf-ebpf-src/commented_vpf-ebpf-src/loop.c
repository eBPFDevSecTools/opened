// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;

struct test_md
{
    uint8_t* data_start;
    uint8_t* data_end;
};

#define ARRAY_LENGTH 40

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 13,
  "endLine": 31,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/loop.c",
  "funcName": "foo",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct test_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "socket_filter",
    "raw_tracepoint_writable",
    "sk_reuseport",
    "lwt_seg6local",
    "cgroup_skb",
    "sock_ops",
    "lwt_out",
    "sched_act",
    "raw_tracepoint",
    "lwt_xmit",
    "xdp",
    "kprobe",
    "sk_msg",
    "cgroup_device",
    "lwt_in",
    "cgroup_sysctl",
    "flow_dissector",
    "tracepoint",
    "cgroup_sock_addr",
    "cgroup_sock",
    "sched_cls",
    "perf_event",
    "sk_skb"
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
__attribute__((section("test_md"), used)) int
foo(struct test_md* ctx)
{
    int index;
    int cumul = 0;
    uint8_t array[ARRAY_LENGTH] = {0};

    for (index = 0; index < sizeof(array); index++) {
        if ((ctx->data_start + index) >= ctx->data_end)
            break;

        array[index] = 1;
    }

    for (index = 0; index < sizeof(array); index++) {
        cumul += array[index];
    }
    return cumul;
}
