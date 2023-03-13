// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

static int (*get_prandom_u32)() = (void*)7;

struct ctx;

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
  "startLine": 8,
  "endLine": 26,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/byteswap.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [
    "get_prandom_u32"
  ],
  "compatibleHookpoints": [
    "sk_msg",
    "lwt_seg6local",
    "raw_tracepoint",
    "lwt_xmit",
    "xdp",
    "perf_event",
    "kprobe",
    "lwt_in",
    "sk_skb",
    "sk_reuseport",
    "socket_filter",
    "sched_cls",
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
    "int func (struct ctx *ctx)\n",
    "{\n",
    "    int rand32 = get_prandom_u32 ();\n",
    "    if (rand32 & 0x01) {\n",
    "        asm volatile (\"r0 = le64 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    else if (rand32 & 0x02) {\n",
    "        asm volatile (\"r0 = le32 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    else if (rand32 & 0x04) {\n",
    "        asm volatile (\"r0 = le16 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    else if (rand32 & 0x10) {\n",
    "        asm volatile (\"r0 = be64 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    else if (rand32 & 0x20) {\n",
    "        asm volatile (\"r0 = be32 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    else {\n",
    "        asm volatile (\"r0 = be16 r0\\nexit\"\n",
    "            );\n",
    "    }\n",
    "    return 0;\n",
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
int func(struct ctx* ctx)
{
   int rand32 = get_prandom_u32();

    if (rand32 & 0x01) {
        asm volatile("r0 = le64 r0\nexit");
    } else if (rand32 & 0x02) {
        asm volatile("r0 = le32 r0\nexit");
    } else if (rand32 & 0x04) {
        asm volatile("r0 = le16 r0\nexit");
    } else if (rand32 & 0x10) {
        asm volatile("r0 = be64 r0\nexit");
    } else if (rand32 & 0x20) {
        asm volatile("r0 = be32 r0\nexit");
    } else {
        asm volatile("r0 = be16 r0\nexit");
    }
    return 0;
}
