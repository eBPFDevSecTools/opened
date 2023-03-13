/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
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
    "lwt_out",
    "sk_reuseport",
    "sched_cls",
    "sk_msg",
    "cgroup_sock_addr",
    "xdp",
    "lwt_in",
    "cgroup_skb",
    "sched_act",
    "cgroup_device",
    "lwt_xmit",
    "raw_tracepoint",
    "cgroup_sysctl",
    "flow_dissector",
    "tracepoint",
    "raw_tracepoint_writable",
    "cgroup_sock",
    "perf_event",
    "lwt_seg6local",
    "sock_ops",
    "sk_skb",
    "kprobe",
    "socket_filter"
  ],
  "source": [
    "int hello (void *ctx)\n",
    "{\n",
    "    bpf_trace_printk (\"Hello, World!\\\\n\");\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
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
