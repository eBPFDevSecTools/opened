// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

static int (*get_prandom_u32)() = (void*)7;

struct ctx;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
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
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
