#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/aio.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/af_unix.h>

#define MAX_PKT 512
struct recv_data_t {
    u32 recv_len;
    u8  pkt[MAX_PKT];
};

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(unix_data, struct recv_data_t, 1);

BPF_PERF_OUTPUT(unix_recv_events);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "int",
          "Description": "For tracing programs , safely attempt to read <[ size ]>(IP: 1) bytes from address <[ src ]>(IP: 2) and store the data in dst. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_probe_read",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  u32 ,Var: size}",
            "{Type:  const void ,Var: *src}"
          ]
        },
        {
          "Return Type": "u64",
          "Return": " A 64-bit integer containing the current tgid and pid, and created  as  such:                     current_task->tgid << 32 | current_task->pid.",
          "Function Name": "bpf_get_current_pid_tgid",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ],
          "Description": "A 64-bit integer containing the current tgid and pid , and created as such: current_task->tgid << 32 | current_task->pid. "
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_current_pid_tgid": [
      {
        "opVar": "    u64 pid_tgid ",
        "inpVar": [
          " "
        ]
      }
    ],
    "bpf_probe_read": [
      {
        "opVar": "NA",
        "inpVar": [
          "    data->pkt",
          " data_len",
          " iodata"
        ]
      }
    ]
  },
  "startLine": 24,
  "endLine": 51,
  "File": "/root/examples/bcc/undump.c",
  "funcName": "trace_unix_stream_read_actor",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_probe_read",
    "bpf_get_current_pid_tgid"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "raw_tracepoint_writable",
    "kprobe",
    "tracepoint"
  ],
  "humanFuncDescription": [
    {
      "description": "The structure 'recv_data_t' stores the length of the receive data in a variable named 'recv_len' of type u32 and the array 'pkt' store the received packet data which is of type u8. The array 'pkt' can store maximum 512B of data. BPF_PERCPU_ARRAY(unix_data, struct recv_data_t, 1) creates creates per_cpu_array map with a single element where key is of type int and value recv_data_t.BPF_PERF_OUTPUT(unix_recv_events) Creates a BPF table named 'unix_recv_events' for pushing out custom event data to user space via a perf ring buffer, When there is an incoming UNIX packet received on a socket, this fucntion is invoked to trace the packet data. If a particular process id is given it traces the data received by that process. When the recieve event occurs, it push the context and data to the perf buffer 'unix_recv_event'.The function also allows tracing data only for specific pids.",
      "author": "Utkalika",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "19.01.2023"
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
int trace_unix_stream_read_actor(struct pt_regs *ctx)
{
    u32 zero = 0;
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    FILTER_PID

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    struct recv_data_t *data = unix_data.lookup(&zero);
    if (!data)
        return 0;

    unsigned int data_len = skb->len;
    if(data_len > MAX_PKT)
        return 0;

    void *iodata = (void *)skb->data;
    data->recv_len = data_len;

    bpf_probe_read(data->pkt, data_len, iodata);
    unix_recv_events.perf_submit(ctx, data, data_len+sizeof(u32));

    return 0;
}
