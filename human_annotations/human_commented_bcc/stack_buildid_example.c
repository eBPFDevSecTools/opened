#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct key_t {
    u32 pid;
    int user_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_STACK_TRACE_BUILDID(stack_traces, 128);

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
          "    &key.name",
          " sizeofkey.name"
        ]
      }
    ]
  },
  "startLine": 13,
  "endLine": 26,
  "File": "/root/examples/bcc/stack_buildid_example.c",
  "funcName": "do_perf_event",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_perf_event_data *ctx"
  ],
  "output": "int",
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
      "description": "do_perf_event() function takes as input a structure ctx 
                      of type bpf_perf_event_data. It uses helper function 
                      bpf_get_current_pid_tgid() to get process id and thread 
                      id and then filters only the pid (32 bits). A map is 
                      created to map the key to current PID. Helper function 
                      bpf_get_current_comm then populates the name mapped to 
                      the key's address with the current process command. Then 
                      it calls get_Stackid() to find unique id for this 
                      stack trace. If this is greater than zero then we increment
                      the key. This gives us a count of the number of times this 
                      PID command combination has been seen. Function returns 0 on
                      successful completion.",
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
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // create map key
    struct key_t key = {.pid = pid};
    bpf_get_current_comm(&key.name, sizeof(key.name));

    key.user_stack_id = stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK);

    if (key.user_stack_id >= 0) {
      counts.increment(key);
    }
    return 0;
}
