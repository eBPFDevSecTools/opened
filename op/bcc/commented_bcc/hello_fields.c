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
    "cgroup_sock",
    "cgroup_sysctl",
    "sock_ops",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_out",
    "cgroup_skb",
    "lwt_xmit",
    "kprobe",
    "sched_cls",
    "tracepoint",
    "sk_reuseport",
    "flow_dissector",
    "sk_skb",
    "sched_act",
    "xdp",
    "sk_msg",
    "perf_event",
    "raw_tracepoint_writable",
    "cgroup_device",
    "lwt_in",
    "raw_tracepoint",
    "lwt_seg6local"
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
