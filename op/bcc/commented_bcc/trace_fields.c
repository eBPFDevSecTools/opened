//int hello (void *ctx)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2,
  "endLine": 6,
  "File": "/home/sayandes/opened_extraction/examples/bcc/trace_fields.c",
  "funcName": "hello",
  "developer_inline_comments": [],
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
    "sk_skb",
    "sched_act",
    "socket_filter",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "lwt_xmit",
    "cgroup_device",
    "lwt_out",
    "raw_tracepoint",
    "lwt_seg6local",
    "raw_tracepoint_writable",
    "sk_msg",
    "cgroup_skb",
    "xdp",
    "tracepoint",
    "cgroup_sock",
    "sk_reuseport",
    "sock_ops",
    "perf_event",
    "lwt_in",
    "kprobe",
    "flow_dissector",
    "sched_cls"
  ],
  "source": [
    "int hello ()\n",
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
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
