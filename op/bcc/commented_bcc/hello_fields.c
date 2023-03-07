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
    "sk_msg",
    "lwt_xmit",
    "kprobe",
    "cgroup_device",
    "cgroup_skb",
    "cgroup_sock_addr",
    "sk_skb",
    "raw_tracepoint",
    "xdp",
    "lwt_in",
    "sock_ops",
    "socket_filter",
    "raw_tracepoint_writable",
    "flow_dissector",
    "perf_event",
    "cgroup_sysctl",
    "sched_cls",
    "lwt_out",
    "lwt_seg6local",
    "sk_reuseport",
    "cgroup_sock",
    "sched_act",
    "tracepoint"
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
