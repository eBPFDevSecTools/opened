#include <linux/blk_types.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/time64.h>

BPF_PERCPU_ARRAY(lat_100ms, u64, 100);
BPF_PERCPU_ARRAY(lat_1ms, u64, 100);
BPF_PERCPU_ARRAY(lat_10us, u64, 100);

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "u64",
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": " Current ktime.",
          "Function Name": "bpf_ktime_get_ns",
          "Input Params": [
            "{Type: voi ,Var: void}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_ktime_get_ns": [
      {
        "opVar": "        dur ",
        "inpVar": [
          "  - rq->io_start_time_ns"
        ]
      }
    ]
  },
  "startLine": 10,
  "endLine": 36,
  "File": "/root/examples/bcc/biolatpcts.c",
  "funcName": "RAW_TRACEPOINT_PROBE",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "block_rq_complete"
  ],
  "output": "NA",
  "helper": [
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_cls",
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
    "sched_act"
  ],
  "humanFuncDescription": [
    {
      "description": "biolatpcts_RAW_TRACEPOINT_PROBE function takes as input a block_req_complete
                      and calculates the duration of the i/o time 'dur' by subtracting kernel time 
                      with start time. It uses helper bpf_ktime_get_ns() to get the kernel time. It 
                      then divides it into three slots:
                      dur>100ms, 100ms>dur>1ms and 10microsec<dur<1ms and increments the count of each 
                      slot if the duration falls in the slot. biolatpcts_RAW_TRACEPOINT_PROBE returns 0
                      when the slots are valid or the io start time for request is 0.",
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
RAW_TRACEPOINT_PROBE(block_rq_complete)
{
        // TP_PROTO(struct request *rq, blk_status_t error, unsigned int nr_bytes)
        struct request *rq = (void *)ctx->args[0];
        unsigned int cmd_flags;
        u64 dur;
        size_t base, slot;

        if (!rq->io_start_time_ns)
                return 0;

        dur = bpf_ktime_get_ns() - rq->io_start_time_ns;

        slot = min_t(size_t, div_u64(dur, 100 * NSEC_PER_MSEC), 99);
        lat_100ms.increment(slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, NSEC_PER_MSEC), 99);
        lat_1ms.increment(slot);
        if (slot)
                return 0;

        slot = min_t(size_t, div_u64(dur, 10 * NSEC_PER_USEC), 99);
        lat_10us.increment(slot);
        return 0;
}
