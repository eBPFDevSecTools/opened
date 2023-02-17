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
    "lwt_in",
    "raw_tracepoint_writable",
    "sched_act",
    "tracepoint",
    "cgroup_sysctl",
    "cgroup_sock",
    "perf_event",
    "sock_ops",
    "raw_tracepoint",
    "xdp",
    "lwt_xmit",
    "sk_reuseport",
    "sk_msg",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "lwt_out",
    "cgroup_skb",
    "sk_skb",
    "socket_filter",
    "kprobe",
    "cgroup_device",
    "flow_dissector",
    "sched_cls"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
    {}
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
