#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 4,
  "endLine": 7,
  "File": "/root/examples/bcc/strlen_hist_ifunc.c",
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


BPF_PERF_OUTPUT(impl_func_addr);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 11,
  "endLine": 14,
  "File": "/root/examples/bcc/strlen_hist_ifunc.c",
  "funcName": "submit_impl_func_addr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "void",
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
void submit_impl_func_addr(struct pt_regs *ctx) {
    u64 addr = PT_REGS_RC(ctx);
    impl_func_addr.perf_submit(ctx, &addr, sizeof(addr));
}


BPF_PERF_OUTPUT(resolv_func_addr);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 22,
  "File": "/root/examples/bcc/strlen_hist_ifunc.c",
  "funcName": "submit_resolv_func_addr",
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
int submit_resolv_func_addr(struct pt_regs *ctx) {
    u64 rip = PT_REGS_IP(ctx);
    resolv_func_addr.perf_submit(ctx, &rip, sizeof(rip));
    return 0;
}
