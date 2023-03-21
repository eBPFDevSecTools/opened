#include <uapi/linux/ptrace.h>
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "int",
          "Description": "For tracing programs , safely attempt to read <[ size ]>(IP: 1) bytes from address <[ src ]>(IP: 2) and store the data in dst. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_probe_read",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  u32 ,Var: size}",
            "{Type:  const void ,Var: *src}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_probe_read": [
      {
        "opVar": "NA",
        "inpVar": [
          "    _user&path",
          " sizeofpath",
          " void *addr"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    \"path:%s\\\\n\"",
          " path"
        ]
      }
    ]
  },
  "startLine": 2,
  "endLine": 9,
  "File": "/root/examples/bcc/nodejs_http_server.c",
  "funcName": "do_trace",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_probe_read",
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "raw_tracepoint_writable",
    "kprobe",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "nodejs_http_server_do_trace() pulls out an address from ctx, 
                      finds the respective file path and then prints it. It takes as
                      argument a structure ctx of type pt_regs. It uses bpf_usdt_readarg() 
                      to read the sixth parameter and then pulls it in as a string to 
                      path. Then we make addr point to path using bpf_probe_read_user() 
                      and then use bpf_trace_printk() helper function to print the 
                      path as string. Function returns 0 on successful completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "01.02.2023"
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
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
