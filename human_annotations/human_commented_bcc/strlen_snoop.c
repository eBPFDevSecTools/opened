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
        },
        {
          "Return Type": "u64",
          "Return": " A 64-bit integer containing the current tgid and pid, and created  as  such:                     current_task->tgid << 32 | current_task->pid.",
          "Function Name": "bpf_get_current_pid_tgid",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ],
          "Description": "A 64-bit integer containing the current tgid and pid , and created as such: current_task->tgid << 32 | current_task->pid. "
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_current_pid_tgid": [
      {
        "opVar": "    u32 pid ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_probe_read": [
      {
        "opVar": "NA",
        "inpVar": [
          "    _user&str",
          " sizeofstr",
          " void *PT_REGS_PARM1ctx"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    \"%s\\\\n\"",
          " &str"
        ]
      }
    ]
  },
  "startLine": 2,
  "endLine": 15,
  "File": "/root/examples/bcc/strlen_snoop.c",
  "funcName": "printarg",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_probe_read",
    "bpf_trace_printk",
    "bpf_get_current_pid_tgid"
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
      "description": "This function is attached to uprobes. 
                      It instruments the user-level function 'strlen' from 'c' binary using user-level dynamic tracing of the function entry, and attach our C defined function (count) to be called whenever the user-level function is called.
                      Everytime strlen() function in called for a process id, bpf_probe_read_user() read size bytes from user address space to the BPF stack.
                      The data is printed in userspace using bpf_trace_printk",
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
int printarg(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;

    char str[80] = {};
    bpf_probe_read_user(&str, sizeof(str), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s\\n", &str);

    return 0;
};
