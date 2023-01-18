#include <uapi/linux/ptrace.h>
BPF_HISTOGRAM(dist);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 3,
  "endLine": 6,
  "File": "/root/examples/bcc/strlen_hist.c",
  "funcName": "count",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}
