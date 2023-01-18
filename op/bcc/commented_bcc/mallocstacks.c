#include <uapi/linux/ptrace.h>

BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, """ + stacks + """);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 6,
  "endLine": 18,
  "File": "/root/examples/bcc/mallocstacks.c",
  "funcName": "alloc_enter",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " size_t size"
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
int alloc_enter(struct pt_regs *ctx, size_t size) {
    int key = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
    if (key < 0)
        return 0;

    // could also use `calls.increment(key, size);`
    u64 zero = 0, *val;
    val = calls.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val) += size;
    }
    return 0;
};
