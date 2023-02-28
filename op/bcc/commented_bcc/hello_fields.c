/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_trace_printk": [
      {
        "opVar": "NA",
        "inpVar": [
          "    \"Hello",
          " World!\\\\n\""
        ]
      }
    ]
  },
  "startLine": 1,
  "endLine": 4,
  "File": "/root/examples/bcc/hello_fields.c",
  "funcName": "hello",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
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
      "description": "hello() function takes as input a void pointer ctx. It uses 
                      the bpf_trace_printk helper to print the message which is passed 
                      as argument. bpf_trace_printk is a printk()-like facility that 
                      prints message defined in it. Function returns 0 on completion.",
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
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
