// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct sk_buff {
    uint32_t _[19];
    uint32_t data;
    uint32_t data_end;
};

struct ctx;

static int (*bpf_skb_change_head)(struct sk_buff *skb, uint32_t len, uint64_t flags) = (void*) 43;

__attribute__((section("socket_filter"), used))
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Grows headroom of packet associated to <[ skb ]>(IP: 0) and adjusts the offset of the MAC header accordingly , adding <[ len ]>(IP: 1) bytes of space. It automatically extends and reallocates memory as required. This helper can be used on a layer 3 <[ skb ]>(IP: 0) to push a MAC header for redirection into a layer 2 device. All values for <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_change_head",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_skb_change_head": [
      {
        "opVar": "NA",
        "inpVar": [
          "    ctx",
          " 4",
          " 0"
        ]
      }
    ]
  },
  "startLine": 17,
  "endLine": 34,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/packet_reallocate.c",
  "funcName": "reallocate_invalidates",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct sk_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_skb_change_head"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "lwt_xmit",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "int reallocate_invalidates (struct sk_buff *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    if (data + sizeof (int) > data_end)\n",
    "        return 1;\n",
    "    int value = *(int*) data;\n",
    "    *(int*) data = value + 1;\n",
    "    bpf_skb_change_head (ctx, 4, 0);\n",
    "    value = *(int*) data;\n",
    "    *(int*) data = value + 1;\n",
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
int reallocate_invalidates(struct sk_buff* ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data + sizeof(int) > data_end)
        return 1;

    int value = *(int*)data;
    *(int*)data = value + 1;

    bpf_skb_change_head(ctx, 4, 0);

    value = *(int*)data;
    *(int*)data = value + 1;

    return 0;
}
