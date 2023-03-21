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
          "        \"KVM_EXIT exit_reason : %d\\\\n\"",
          " args->exit_reason"
        ]
      }
    ]
  },
  "startLine": 4,
  "endLine": 12,
  "File": "/root/examples/bcc/kvm_hypercall.c",
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
    "sock_ops",
    "sched_cls",
    "cgroup_device",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act",
    "cgroup_sysctl"
  ],
  "humanFuncDescription": [
    {
      "description": "kvm_hypercall_TRACEPOINT_PROBE function is triggered in case of kvm exit
                      event. It takes as input two parameters 'kvm' and 'kvm_exit. Function stores
                      checks if the reason for exit is 'EXIT_REASON'. If yes, it prints the reason 
                      and stores 1 in start map. Basically keeping a note wether the next exit reason 
                      of type 'EXIT_REASON' was triggered by same event reason. Functions returns 0 on
                      success.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "01.02.2023"
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
          "        \"KVM_ENTRY vcpu_id : %u\\\\n\"",
          " args->vcpu_id"
        ]
      }
    ]
  },
  "startLine": 14,
  "endLine": 23,
  "File": "/root/examples/bcc/kvm_hypercall.c",
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
    "sock_ops",
    "sched_cls",
    "cgroup_device",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act",
    "cgroup_sysctl"
  ],
  "humanFuncDescription": [
    {
      "description": "kvm_hypercal_TRACEPOINT_PROBE() checks kvm entry events. It checks 
                      if the reason for exit is EXIT_REASON and if it is, then it prints 
                      out the vcpu id of that event. It also resets start to 0. Function
                      returns 0 on success.",
      "author": "Neha Chowdhary",
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
          "        \"HYPERCALL nr : %d\\\\n\"",
          " args->nr"
        ]
      }
    ]
  },
  "startLine": 25,
  "endLine": 33,
  "File": "/root/examples/bcc/kvm_hypercall.c",
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
    "sock_ops",
    "sched_cls",
    "cgroup_device",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act",
    "cgroup_sysctl"
  ],
  "humanFuncDescription": [
    {
      "description": "kvm_hypercall_TRACEPOINT_PROBE() checks whether a kvm hypercall
                      occurs or not and whether the reason for it's exit is 
                      EXTI_REASON. If yes then we print args->nr related to the
                      hypercall. Function returns 0 on success.",
      "author": "Neha Chowdhary",
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
