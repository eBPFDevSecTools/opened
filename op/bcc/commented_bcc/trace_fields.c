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
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "//int hello (void *ctx)"
    }
  ],
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
    "lwt_out",
    "lwt_seg6local",
    "sk_reuseport",
    "kprobe",
    "lwt_in",
    "flow_dissector",
    "sk_msg",
    "perf_event",
    "sched_cls",
    "sock_ops",
    "xdp",
    "raw_tracepoint",
    "sched_act",
    "lwt_xmit",
    "tracepoint",
    "sk_skb",
    "cgroup_sock",
    "cgroup_skb",
    "cgroup_sock_addr",
    "cgroup_sysctl",
    "cgroup_device",
    "socket_filter",
    "raw_tracepoint_writable"
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
