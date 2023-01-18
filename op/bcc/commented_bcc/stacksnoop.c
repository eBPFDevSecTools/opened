#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 stack_id;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 128);
BPF_PERF_OUTPUT(events);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "int",
          "Description": "Copy the comm attribute of the current task into <[ buf ]>(IP: 0) of size_of_buf. The comm attribute contains the name of the executable (excluding the path) for the current task. The <[ size_of_buf ]>(IP: 1) must be strictly positive. On success , the helper makes sure that the <[ buf ]>(IP: 0) is NUL-terminated. On failure , it is filled with zeroes. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_get_current_comm",
          "Input Params": [
            "{Type: char ,Var: *buf}",
            "{Type:  u32 ,Var: size_of_buf}"
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
          "  >> 32"
        ]
      }
    ],
    "bpf_get_current_comm": [
      {
        "opVar": "NA",
        "inpVar": [
          "    &data.comm",
          " sizeofdata.comm"
        ]
      }
    ]
  },
  "startLine": 13,
  "endLine": 21,
  "File": "/root/examples/bcc/stacksnoop.c",
  "funcName": "trace_stack",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "void",
  "helper": [
    "bpf_get_current_comm",
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
void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, 0),
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}
