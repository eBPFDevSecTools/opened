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
      "description": " Using BPF_PERF_OUTPUT a Perf event map is declared named impl_func_addr. 
                       This will instrument strlen() function from libc, and call our BPF function submit_impl_func_addr() when it returns.
                       PT_REGS_RC is a macro that’s going to read the returned value from BPF register for this specific context and will be stored in the addr varibale of type u64.
                       perf_submit function updates the Perf impl_func_addr map with the returned address value.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "13.02.2023"
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
      "description": "Using BPF_PERF_OUTPUT a Perf event map is declared named resolv_func_addr. 
                      This will instrument strlen() function from libc, and when it is called, the BPF function submit_resolv_func_addr() will be called.
                      PT_REGS_IP is a macro that’s going to read the returned value from BPF register for this specific context and will be stored in the rip varibale of type u64.
                      perf_submit function updates the Perf resolv_func_addr map with the returned address value.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "13.02.2023"
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
