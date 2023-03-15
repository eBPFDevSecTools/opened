/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1,
  "endLine": 5,
  "File": "/home/sayandes/opened_extraction/examples/bcc/urandomread.c",
  "funcName": "TRACEPOINT_PROBE",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "random",
    " urandom_read"
  ],
  "output": "NA",
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
    "TRACEPOINT_PROBE (random, urandom_read)\n",
    "{\n",
    "    bpf_trace_printk (\"%d\\\\n\", args->got_bits);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "lookup",
    "update"
  ],
  "call_depth": -1,
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
TRACEPOINT_PROBE (random, urandom_read)
{
	    bpf_trace_printk ("%d\\n", args->got_bits);
	        return 0;
}
