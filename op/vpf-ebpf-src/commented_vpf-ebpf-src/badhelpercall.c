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
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "lwt_xmit",
    "xdp",
    "perf_event",
    "kprobe",
    "lwt_in",
    "cgroup_device",
    "sk_skb",
    "sk_reuseport",
    "socket_filter",
    "sched_cls",
    "cgroup_sysctl",
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
