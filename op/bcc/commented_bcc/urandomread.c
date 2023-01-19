/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
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
  "File": "/home/sayandes/opened_extraction/examples/bcc/urandomread.c",
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
    "tracepoint",
    "sched_cls",
    "sk_msg",
    "cgroup_sock_addr",
    "socket_filter",
    "sk_skb",
    "flow_dissector",
    "sock_ops",
    "lwt_seg6local",
    "kprobe",
    "perf_event",
    "lwt_in",
    "xdp",
    "raw_tracepoint",
    "lwt_out",
    "sk_reuseport",
    "lwt_xmit",
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_sysctl",
    "raw_tracepoint_writable",
    "sched_act",
    "cgroup_device"
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
