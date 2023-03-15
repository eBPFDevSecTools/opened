// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static int (*ebpf_get_current_comm)(char* buffer, uint32_t buffer_size) = (void*) 16;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 15,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/badhelpercall.c",
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
      "start_line": 12,
      "end_line": 12,
      "text": "// The following should fail verification since it asks the helper"
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": "// to write past the end of the stack."
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
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
    "int func ()\n",
    "{\n",
    "    char buffer [1];\n",
    "    return ebpf_get_current_comm (buffer, 20);\n",
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
int func()
{
    char buffer[1];

    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
    return ebpf_get_current_comm(buffer, 20);
}
