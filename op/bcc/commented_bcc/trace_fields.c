//int hello (void *ctx)
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t     \"Hello",
          " World!\\\\n\""
        ]
      }
    ]
  },
  "startLine": 2,
  "endLine": 6,
  "File": "/home/sayandes/opened_extraction/examples/bcc/trace_fields.c",
  "funcName": "hello",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "flow_dissector",
    "sk_msg",
    "raw_tracepoint",
    "lwt_in",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "sock_ops",
    "xdp",
    "sched_cls",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "cgroup_device",
    "cgroup_skb",
    "perf_event",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sched_act"
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
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
