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
        "opVar": "\tdur ",
        "inpVar": [
          "  - rq->io_start_time_ns"
        ]
      }
    ]
  },
  "startLine": 8,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/bcc/biolatpcts.c",
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
    "cgroup_skb",
    "perf_event",
    "sk_skb",
    "tracepoint",
    "cgroup_sock",
    "lwt_seg6local",
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
