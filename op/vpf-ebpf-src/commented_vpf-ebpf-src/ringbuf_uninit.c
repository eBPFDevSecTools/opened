// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct ebpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

#define BPF_MAP_TYPE_RINGBUF 27

static long (*bpf_ringbuf_output)(void *ringbuf, void *data, uint64_t size, uint64_t flags) = (void *) 130;

__attribute__((section("maps"), used))
struct ebpf_map ring_buffer = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 32,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/ringbuf_uninit.c",
  "funcName": "test",
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
      "start_line": 28,
      "end_line": 28,
      "text": "// The following call should fail verification as test is not initialized."
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
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
    "int test (void *ctx)\n",
    "{\n",
    "    uint64_t test;\n",
    "    bpf_ringbuf_output (&ring_buffer, &test, sizeof (test), 0);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ringbuf_output"
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
int
test(void* ctx)
{
    uint64_t test;
    // The following call should fail verification as test is not initialized.
    bpf_ringbuf_output(&ring_buffer, &test, sizeof(test), 0);

    return 0;
}
