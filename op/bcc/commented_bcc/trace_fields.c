//int hello (void *ctx)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
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
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
