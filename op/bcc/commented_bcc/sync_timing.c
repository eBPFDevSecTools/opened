#include <uapi/linux/ptrace.h>

BPF_HASH(last);

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
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_ktime_get_ns": [
      {
        "opVar": "        delta ",
        "inpVar": [
          "  - *tsp"
        ]
      },
      {
        "opVar": "            ts ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "                        \"%d\\\\n\"",
          " delta / 1000000"
        ]
      }
    ]
  },
  "startLine": 5,
  "endLine": 23,
  "File": "/root/examples/bcc/sync_timing.c",
  "funcName": "do_trace",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_cls",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
       "description": " A BPF hash map named 'last' has created which store the timestamps.
                       This function is invoked every time a system call 'sync' is made.
                       It calculate the time difference between current timestamp and the last timestamp stored in the map,
                       and store it variable 'delta' which indicates the time elapsed after that.
                       If 'delta' is less than 1 nano second, then it is printed out to userspace.
                       Once printed the value, that entry gets deleted from 'last' map and then the current timestamp is pushed to the map.",
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
int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
