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
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [
    "trace_printk",
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "cgroup_sock",
    "lwt_in",
    "sk_msg",
    "xdp",
    "cgroup_sysctl",
    "lwt_out",
    "raw_tracepoint",
    "sched_act",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "kprobe",
    "cgroup_sock_addr",
    "cgroup_skb",
    "tracepoint",
    "lwt_xmit",
    "lwt_seg6local",
    "sock_ops",
    "socket_filter",
    "cgroup_device",
    "sk_skb",
    "flow_dissector"
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
