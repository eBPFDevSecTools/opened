// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t _1;
    uint32_t _2;
    uint32_t _3;
};

static int (*get_prandom_u32)() = (void*)7;

__attribute__((section("xdp"), used))
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
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 58,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/packet_access.c",
  "funcName": "test_packet_access",
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
      "start_line": 26,
      "end_line": 26,
      "text": "// We now do two code paths that should have identical results."
    },
    {
      "start_line": 32,
      "end_line": 44,
      "text": "/* The above code results in the following assembly:\n         *            r0 <<= 2\n         *            r0 &= 60\n         *            r1 = *(u32 *)(r6 + 0)\n         *            r1 += r0    // In the ELSE clause below, this becomes\n         *                        // \"r0 += r1\" then \"r1 = r0\".\n         *            r0 = 1\n         *            r2 = r1\n         *            r2 += 4\n         *            r3 = *(u32 *)(r6 + 4)\n         *            if r2 > r3 goto +13\n         *            r0 = *(u32 *)(r1 + 0)\n         */"
    },
    {
      "start_line": 49,
      "end_line": 49,
      "text": "// In the IF clause above, these two instructions"
    },
    {
      "start_line": 50,
      "end_line": 50,
      "text": "// are \"r1 += r0\"."
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "flow_dissector",
    "sched_act",
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
    "int test_packet_access (struct xdp_md *ctx)\n",
    "{\n",
    "    uint32_t rand32 = get_prandom_u32 ();\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    int offset = (rand32 & 0x0F) * 4;\n",
    "    int *ptr;\n",
    "    if (rand32 & 1) {\n",
    "        if (data + offset + sizeof (int) > data_end)\n",
    "            return 1;\n",
    "        ptr = offset + data;\n",
    "        return *(int*) ptr;\n",
    "    }\n",
    "    else {\n",
    "        asm volatile (\"r0 <<= 2\\n\"\n",
    "            \"r0 &= 60\\n\"\n",
    "            \"r1 = *(u32 *)(r6 + 0)\\n\"\n",
    "            \"r0 += r1\\n\"\n",
    "            \"r1 = r0\\n\"\n",
    "            \"r0 = 1\\n\"\n",
    "            \"r2 = r1\\n\"\n",
    "            \"r2 += 4\\n\"\n",
    "            \"r3 = *(u32 *)(r6 + 4)\\n\"\n",
    "            \"if r2 > r3 goto +1\\n\"\n",
    "            \"r0 = *(u32 *)(r1 + 0)\\n\"\n",
    "            );\n",
    "    }\n",
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
int test_packet_access(struct xdp_md* ctx)
{
    uint32_t rand32 = get_prandom_u32();
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int offset = (rand32 & 0x0F) * 4;
    int* ptr;

    // We now do two code paths that should have identical results.
    if (rand32 & 1) {
        if (data + offset + sizeof(int) > data_end)
            return 1;
        ptr = offset + data;
        return *(int*)ptr;
        /* The above code results in the following assembly:
         *            r0 <<= 2
         *            r0 &= 60
         *            r1 = *(u32 *)(r6 + 0)
         *            r1 += r0    // In the ELSE clause below, this becomes
         *                        // "r0 += r1" then "r1 = r0".
         *            r0 = 1
         *            r2 = r1
         *            r2 += 4
         *            r3 = *(u32 *)(r6 + 4)
         *            if r2 > r3 goto +13
         *            r0 = *(u32 *)(r1 + 0)
         */
    } else {
        asm volatile("r0 <<= 2\n"
                     "r0 &= 60\n"
                     "r1 = *(u32 *)(r6 + 0)\n"
                     "r0 += r1\n" // In the IF clause above, these two instructions
                     "r1 = r0\n"  // are "r1 += r0".
                     "r0 = 1\n"
                     "r2 = r1\n"
                     "r2 += 4\n"
                     "r3 = *(u32 *)(r6 + 4)\n"
                     "if r2 > r3 goto +1\n"
                     "r0 = *(u32 *)(r1 + 0)\n");
    }
}
