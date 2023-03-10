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
    "TRACEPOINT_PROBE",
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
    "TRACEPOINT_PROBE (random, urandom_read)\n",
    "{\n",
    "    bpf_trace_printk (\"%d\\\\n\", args->got_bits);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "update",
    "lookup"
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
