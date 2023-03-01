BPF_PERF_OUTPUT(events);
BPF_ARRAY(counters, u64, 10);
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
        "opVar": "NA",
        "inpVar": [
          "",
          " 0x12345678"
        ]
      }
    ],
    "bpf_trace_printk": [
      {
        "opVar": "  if ((rc ",
        "inpVar": [
          " events.perf_submitctx",
          " &data",
          " sizeofdata < 0    \"perf_output failed: %d\\\\n\"",
          " rc"
        ]
      }
    ]
  },
  "startLine": 3,
  "endLine": 15,
  "File": "/root/examples/bcc/trace_perf_output.c",
  "funcName": "do_sys_clone",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
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
     "description": " BPF_ARRAY(counters, u64, 10) creates a array named 'counter' with 10 buckets and u64 values.
                      BPF_PERF_OUTPUT(events) creates a BPF table named 'events' for pushing out custom event data to user space via a perf ring buffer.
                      This function in attahced with system call 'clone'.
                      Whenever the event occurs, the event data gets submitted to user space via a perf ring buffer.
                      The event data is a structure consist of system current time and the magic number i.e. 0x12345678
                      Once the event data is submmited to the perf buffer successfully, it increaments the counter value which indicates the number of times the event has been occured",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "19.01.2023 "
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
int do_sys_clone(void *ctx) {
  struct {
    u64 ts;
    u64 magic;
  } data = {bpf_ktime_get_ns(), 0x12345678};
  int rc;
  if ((rc = events.perf_submit(ctx, &data, sizeof(data))) < 0)
    bpf_trace_printk("perf_output failed: %d\\n", rc);
  int zero = 0;
  u64 *val = counters.lookup(&zero);
  if (val) lock_xadd(val, 1);
  return 0;
}
