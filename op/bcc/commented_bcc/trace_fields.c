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
  "File": "/root/examples/bcc/trace_fields.c",
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
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
