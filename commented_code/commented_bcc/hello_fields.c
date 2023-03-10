/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\"Hello",
          " World!\\\\n\""
        ]
      }
    ]
  },
  "startLine": 1,
  "endLine": 4,
  "File": "/home/sayandes/opened_extraction/examples/bcc/hello_fields.c",
  "funcName": "hello",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint_writable",
    "lwt_xmit",
    "sock_ops",
    "lwt_out",
    "sk_reuseport",
    "flow_dissector",
    "cgroup_sysctl",
    "tracepoint",
    "cgroup_sock_addr",
    "xdp",
    "lwt_seg6local",
    "socket_filter",
    "cgroup_device",
    "sched_act",
    "kprobe",
    "perf_event",
    "lwt_in",
    "cgroup_skb",
    "cgroup_sock",
    "sched_cls",
    "sk_skb",
    "sk_msg",
    "raw_tracepoint"
  ],
  "source": [
    "int hello (void *ctx)\n",
    "{\n",
    "    bpf_trace_printk (\"Hello, World!\\\\n\");\n",
    "    return 0;\n",
    "}\n"
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
int hello(void *ctx) {
	bpf_trace_printk("Hello, World!\\n");
	return 0;
}
