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
      "description": "  A histogram named dist is created, which defaults to 64 buckets (0-63) indexed by keys of type int.  
                        This function increments the value of dist by 1. Each bin represents one bit of the return code from the syscall being traced.
                        PT_REGS_RC(ctx) returned value from BPF register for the specific context *ctx.
                        This function basically counts the strlen() and updates its histogram.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "02.02.2023"
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
