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
