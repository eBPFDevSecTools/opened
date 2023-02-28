#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        },
        {
          "Return Type": "int",
          "Description": "Copy the comm attribute of the current task into <[ buf ]>(IP: 0) of size_of_buf. The comm attribute contains the name of the executable (excluding the path) for the current task. The <[ size_of_buf ]>(IP: 1) must be strictly positive. On success , the helper makes sure that the <[ buf ]>(IP: 0) is NUL-terminated. On failure , it is filled with zeroes. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_get_current_comm",
          "Input Params": [
            "{Type: char ,Var: *buf}",
            "{Type:  u32 ,Var: size_of_buf}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_ktime_get_ns": [
      {
        "opVar": "    data.ts ",
        "inpVar": [
          " "
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
  "startLine": 11,
  "endLine": 24,
  "File": "/root/examples/bcc/hello_perf_output_using_ns.c",
  "funcName": "hello",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_get_current_comm"
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
      "description": "hello() function takes as input a structure ctx of type pt_regs.
                      It has two data structures 'data' to store data of an event and 'ns' 
                      to store PID namespace of the event. bpf_get_ns_current_pid_tgid() 
                      helper function returns values for pid and tgid as seen from the 
                      current namespace will be returned in 'ns'. Accordingly the PID and 
                      timestamp are updated for the event. Then we populate the first argument 
                      address 'data.comm' with the current process command and submit the event for
                      user space to read via a perf ring buffer. Function returns 0 on success.",
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
int hello(struct pt_regs *ctx) {
    struct data_t data = {};
    struct bpf_pidns_info ns = {};

    if(bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info)))
	    return 0;
    data.pid = ns.pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
