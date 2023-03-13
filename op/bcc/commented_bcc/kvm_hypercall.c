#define EXIT_REASON 18
BPF_HASH(start, u8, u8);
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 3,
  "endLine": 11,
  "File": "/home/sayandes/opened_extraction/examples/bcc/kvm_hypercall.c",
  "funcName": "TRACEPOINT_PROBE",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "kvm",
    " kvm_exit"
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
    "TRACEPOINT_PROBE (kvm, kvm_exit)\n",
    "{\n",
    "    u8 e = EXIT_REASON;\n",
    "    u8 one = 1;\n",
    "    if (args->exit_reason == EXIT_REASON) {\n",
    "        bpf_trace_printk (\"KVM_EXIT exit_reason : %d\\\\n\", args->exit_reason);\n",
    "        start.update (&e, &one);\n",
    "    }\n",
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
TRACEPOINT_PROBE(kvm, kvm_exit) {
	u8 e = EXIT_REASON;
	u8 one = 1;
	if (args->exit_reason == EXIT_REASON) {
		bpf_trace_printk("KVM_EXIT exit_reason : %d\\n", args->exit_reason);
		start.update(&e, &one);
	}
	return 0;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 12,
  "endLine": 21,
  "File": "/home/sayandes/opened_extraction/examples/bcc/kvm_hypercall.c",
  "funcName": "TRACEPOINT_PROBE",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "kvm",
    " kvm_entry"
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
    "TRACEPOINT_PROBE (kvm, kvm_entry)\n",
    "{\n",
    "    u8 e = EXIT_REASON;\n",
    "    u8 zero = 0;\n",
    "    u8 *s = start.lookup (&e);\n",
    "    if (s != NULL && *s == 1) {\n",
    "        bpf_trace_printk (\"KVM_ENTRY vcpu_id : %u\\\\n\", args->vcpu_id);\n",
    "        start.update (&e, &zero);\n",
    "    }\n",
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
TRACEPOINT_PROBE(kvm, kvm_entry) {
	u8 e = EXIT_REASON;
	u8 zero = 0;
	u8 *s = start.lookup(&e);
	if (s != NULL && *s == 1) {
		bpf_trace_printk("KVM_ENTRY vcpu_id : %u\\n", args->vcpu_id);
		start.update(&e, &zero);
	}
	return 0;
}
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 30,
  "File": "/home/sayandes/opened_extraction/examples/bcc/kvm_hypercall.c",
  "funcName": "TRACEPOINT_PROBE",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "kvm",
    " kvm_hypercall"
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
    "TRACEPOINT_PROBE (kvm, kvm_hypercall)\n",
    "{\n",
    "    u8 e = EXIT_REASON;\n",
    "    u8 zero = 0;\n",
    "    u8 *s = start.lookup (&e);\n",
    "    if (s != NULL && *s == 1) {\n",
    "        bpf_trace_printk (\"HYPERCALL nr : %d\\\\n\", args->nr);\n",
    "    }\n",
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
TRACEPOINT_PROBE(kvm, kvm_hypercall) {
	u8 e = EXIT_REASON;
	u8 zero = 0;
	u8 *s = start.lookup(&e);
	if (s != NULL && *s == 1) {
		bpf_trace_printk("HYPERCALL nr : %d\\n", args->nr);
	}
	return 0;
};
