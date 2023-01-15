/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t     \"%d\\\\n\"",
          " args->got_bits"
        ]
      }
    ]
  },
  "startLine": 1,
  "endLine": 5,
  "File": "/root/examples/bcc/urandomread.c",
  "funcName": "TRACEPOINT_PROBE",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "random",
    " urandom_read"
  ],
  "output": "NA",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint_writable",
    "sk_skb",
    "xdp",
    "socket_filter",
    "lwt_seg6local",
    "cgroup_device",
    "cgroup_sock",
    "tracepoint",
    "cgroup_sysctl",
    "lwt_out",
    "sock_ops",
    "cgroup_skb",
    "sched_cls",
    "lwt_in",
    "sk_msg",
    "sched_act",
    "lwt_xmit",
    "flow_dissector",
    "kprobe",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "sk_reuseport",
    "perf_event"
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
TRACEPOINT_PROBE (random, urandom_read)
{
	    bpf_trace_printk ("%d\\n", args->got_bits);
	        return 0;
}
