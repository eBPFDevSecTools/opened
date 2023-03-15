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
    "xdp",
    "cgroup_device",
    "raw_tracepoint_writable",
    "lwt_xmit",
    "raw_tracepoint",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "kprobe",
    "lwt_seg6local",
    "lwt_out",
    "sk_msg",
    "sched_act",
    "flow_dissector",
    "socket_filter",
    "cgroup_sysctl",
    "cgroup_sock",
    "sk_skb",
    "sock_ops",
    "cgroup_sock_addr",
    "sk_reuseport",
    "sched_cls",
    "lwt_in"
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
