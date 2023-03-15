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
    "sock_ops",
    "sk_skb",
    "flow_dissector",
    "socket_filter",
    "sk_reuseport",
    "raw_tracepoint",
    "kprobe",
    "xdp",
    "lwt_in",
    "cgroup_sysctl",
    "lwt_xmit",
    "cgroup_sock_addr",
    "sched_cls",
    "perf_event",
    "sched_act",
    "lwt_out",
    "raw_tracepoint_writable",
    "tracepoint",
    "cgroup_device",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_skb"
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
