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
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct test_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "flow_dissector",
    "sched_act",
    "cgroup_device",
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
    "cgroup_sysctl",
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
    "int foo (struct test_md *ctx)\n",
    "{\n",
    "    int index;\n",
    "    int cumul = 0;\n",
    "    uint8_t array [ARRAY_LENGTH] = {0};\n",
    "    for (index = 0; index < sizeof (array); index++) {\n",
    "        if ((ctx->data_start + index) >= ctx->data_end)\n",
    "            break;\n",
    "        array[index] = 1;\n",
    "    }\n",
    "    for (index = 0; index < sizeof (array); index++) {\n",
    "        cumul += array[index];\n",
    "    }\n",
    "    return cumul;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
