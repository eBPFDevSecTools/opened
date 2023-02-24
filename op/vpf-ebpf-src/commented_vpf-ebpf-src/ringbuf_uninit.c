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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "cgroup_sock",
    "lwt_in",
    "flow_dissector",
    "perf_event",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sched_act",
    "sched_cls",
    "sk_skb",
    "xdp",
    "sock_ops",
    "lwt_out",
    "cgroup_sysctl",
    "lwt_xmit",
    "tracepoint",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device",
    "cgroup_skb",
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "socket_filter"
  ],
  "source": [
    "int test (void *ctx)\n",
    "{\n",
    "    uint64_t test;\n",
    "    bpf_ringbuf_output (&ring_buffer, &test, sizeof (test), 0);\n",
    "    return 0;\n",
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
int
test(void* ctx)
{
    uint64_t test;
    // The following call should fail verification as test is not initialized.
    bpf_ringbuf_output(&ring_buffer, &test, sizeof(test), 0);

    return 0;
}
