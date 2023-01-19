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
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "get_prandom_u32": [
      {
        "opVar": "    uint32_t rand32 ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 18,
  "endLine": 58,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/packet_access.c",
  "funcName": "test_packet_access",
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
