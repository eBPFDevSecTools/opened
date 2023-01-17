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
  "File": "/home/palani/github/opened_extraction/examples/bcc/urandomread.c",
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
    "flow_dissector",
    "perf_event",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "lwt_in",
    "tracepoint",
    "sk_reuseport",
    "xdp",
    "sock_ops",
    "cgroup_sock",
    "cgroup_device",
    "cgroup_sysctl",
    "socket_filter",
    "sched_act",
    "sched_cls",
    "sk_msg",
    "cgroup_skb",
    "sk_skb",
    "raw_tracepoint",
    "cgroup_sock_addr",
    "kprobe",
    "lwt_out",
    "lwt_xmit"
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
