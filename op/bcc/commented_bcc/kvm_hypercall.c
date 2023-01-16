#define EXIT_REASON 18
BPF_HASH(start, u8, u8);
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\"KVM_EXIT exit_reason : %d\\\\n\"",
          " args->exit_reason"
        ]
      }
    ]
  },
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
    "flow_dissector",
    "sk_msg",
    "raw_tracepoint",
    "lwt_in",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "sock_ops",
    "xdp",
    "sched_cls",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "cgroup_device",
    "cgroup_skb",
    "perf_event",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\"KVM_ENTRY vcpu_id : %u\\\\n\"",
          " args->vcpu_id"
        ]
      }
    ]
  },
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
    "flow_dissector",
    "sk_msg",
    "raw_tracepoint",
    "lwt_in",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "sock_ops",
    "xdp",
    "sched_cls",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "cgroup_device",
    "cgroup_skb",
    "perf_event",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "\t\t\"HYPERCALL nr : %d\\\\n\"",
          " args->nr"
        ]
      }
    ]
  },
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
    "flow_dissector",
    "sk_msg",
    "raw_tracepoint",
    "lwt_in",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "sock_ops",
    "xdp",
    "sched_cls",
    "lwt_xmit",
    "socket_filter",
    "sk_reuseport",
    "lwt_out",
    "kprobe",
    "cgroup_device",
    "cgroup_skb",
    "perf_event",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_seg6local",
    "cgroup_sysctl",
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
