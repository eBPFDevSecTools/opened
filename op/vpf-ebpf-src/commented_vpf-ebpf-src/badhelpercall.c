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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_skb",
    "cgroup_sock_addr",
    "lwt_out",
    "lwt_xmit",
    "sock_ops",
    "raw_tracepoint",
    "perf_event",
    "sk_reuseport",
    "flow_dissector",
    "cgroup_sysctl",
    "sched_act",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_skb",
    "sched_cls",
    "lwt_in",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device",
    "xdp",
    "tracepoint",
    "socket_filter"
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
