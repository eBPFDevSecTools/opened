#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

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
          "    _user&key.c",
          " sizeofkey.c",
          " void *PT_REGS_PARM1ctx"
        ]
      }
    ]
  },
  "startLine": 8,
  "endLine": 22,
  "File": "/root/examples/bcc/strlen_count.c",
  "funcName": "count",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_probe_read"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "kprobe",
    "raw_tracepoint_writable",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "This function is attached to uprobes. 
                      It instruments the user-level function 'strlen' from 'c' binary using user-level dynamic tracing of the function entry, and attach our C defined function (count) to be called whenever the user-level function is called.
                      A BPF HASH named 'counts' is created which stores struct key_t.
                      Everytime strlen() function in called, bpf_probe_read_user() read key.c bytes from user address space to the BPF stack.
                      A lookup operation is made on the counts map with the key. 
                      If it exist then increament it's values otherwise initialize with 0.
                      ",
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
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
