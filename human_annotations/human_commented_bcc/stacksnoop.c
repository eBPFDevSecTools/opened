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
      "description": "A stack trace map named stack_traces is created to store the stack trace of processes, with a maximum number of stack trace entries of 1024.
                      A BPF table named events is created to push event data to user space via a perf ring buffer.
                      Using bpf_get_current_pid_tgid() helper function the upper 32 bits is extracted which is the pid to the userspace view.
                      A structure named data_t stores the stack_id of type u64, pid of type u32 and a character array named comm of size 16.
                      stack_traces.get_stackid(ctx, 0) walks the stack found via the struct pt_regs in ctx, saves it in the stack trace map, and returns a unique ID for the stack trace.
                      bpf_get_current_comm(&data.comm, sizeof(data.comm)) populates the first argument address with the current process name.
                      The data is pushed to the event map using perf_submit so that the userspace can read these data.",
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
void trace_stack(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER
    struct data_t data = {};
    data.stack_id = stack_traces.get_stackid(ctx, 0),
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
}
