#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 curr_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
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
        "opVar": "    key.curr_pid ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 10,
  "endLine": 23,
  "File": "/root/examples/bcc/task_switch.c",
  "funcName": "count_sched",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " struct task_struct *prev"
  ],
  "output": "int",
  "helper": [
    "bpf_get_current_pid_tgid"
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
       "description": "A BPF map named 'stats' is created where the key is struct *key_t. key_t stores the current pid and previous process's id
                      This function is invoked everytime a context switch occurs.
                      When there is a task switch, it stores the pid as prev pid and the new process pid in curr_pid of struct key.
                      Then a look up is performed with the key in the stats BPF map. 
                      If the pid does not present in the map, it initializes it with 0, otherwise the count is increased by 1 for the pid",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "21.01.2023"
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
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;

    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
