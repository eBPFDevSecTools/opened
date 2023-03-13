/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1,
  "endLine": 5,
  "File": "/home/sayandes/opened_extraction/examples/bcc/urandomread.c",
  "funcName": "TRACEPOINT_PROBE",
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
