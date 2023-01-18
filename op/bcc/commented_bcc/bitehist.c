#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist_linear);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 7,
  "endLine": 12,
  "File": "/root/examples/bcc/bitehist.c",
  "funcName": "trace_req_done",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " struct request *req"
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
int trace_req_done(struct pt_regs *ctx, struct request *req)
{
    dist.increment(bpf_log2l(req->__data_len / 1024));
    dist_linear.increment(req->__data_len / 1024);
    return 0;
}
