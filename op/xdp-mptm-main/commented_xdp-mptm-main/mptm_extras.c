/* SPDX-License-Identifier: GPL-2.0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <kernel/lib/mptm-debug.h>

#define MAX_ENTRIES 1024

struct bpf_map_def SEC("maps") mptm_extras_redirect_devmap = {
    .type        = BPF_MAP_TYPE_DEVMAP,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_ENTRIES,
};

SEC("mptm_redirect_xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm_extras.c",
  "funcName": "mptm_redirect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_redirect_map",
    "redirect",
    "bpf_redirect",
    "redirect_map"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int mptm_redirect (struct xdp_md *ctx)\n",
    "{\n",
    "    __u64 flags = 0;\n",
    "    __u32 key = ctx->ingress_ifindex;\n",
    "    return bpf_redirect_map (&mptm_extras_redirect_devmap, key, flags);\n",
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
int mptm_redirect(struct xdp_md *ctx) {
    __u64 flags = 0;
    __u32 key = ctx->ingress_ifindex;

    return bpf_redirect_map(&mptm_extras_redirect_devmap, key, flags);
}

SEC("mptm_pass_xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 32,
  "endLine": 34,
  "File": "/home/sayandes/opened_extraction/examples/xdp-mptm-main/src/kernel/mptm_extras.c",
  "funcName": "mptm_pass",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int mptm_pass (struct xdp_md *ctx)\n",
    "{\n",
    "    return XDP_PASS;\n",
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
int mptm_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

