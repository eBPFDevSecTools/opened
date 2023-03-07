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
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
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
    "sk_msg",
    "lwt_xmit",
    "kprobe",
    "cgroup_skb",
    "cgroup_sock_addr",
    "sk_skb",
    "raw_tracepoint",
    "xdp",
    "lwt_in",
    "sock_ops",
    "socket_filter",
    "raw_tracepoint_writable",
    "flow_dissector",
    "perf_event",
    "sched_cls",
    "lwt_out",
    "lwt_seg6local",
    "sk_reuseport",
    "cgroup_sock",
    "sched_act",
    "tracepoint"
  ],
  "source": [
    "RAW_TRACEPOINT_PROBE (block_rq_complete)\n",
    "{\n",
    "    struct request *rq = (void *) ctx->args[0];\n",
    "    unsigned int cmd_flags;\n",
    "    u64 dur;\n",
    "    size_t base, slot;\n",
    "    if (!rq->io_start_time_ns)\n",
    "        return 0;\n",
    "    dur = bpf_ktime_get_ns () - rq->io_start_time_ns;\n",
    "    slot = min_t (size_t, div_u64 (dur, 100 * NSEC_PER_MSEC), 99);\n",
    "    lat_100ms.increment (slot);\n",
    "    if (slot)\n",
    "        return 0;\n",
    "    slot = min_t (size_t, div_u64 (dur, NSEC_PER_MSEC), 99);\n",
    "    lat_1ms.increment (slot);\n",
    "    if (slot)\n",
    "        return 0;\n",
    "    slot = min_t (size_t, div_u64 (dur, 10 * NSEC_PER_USEC), 99);\n",
    "    lat_10us.increment (slot);\n",
    "    return 0;\n",
    "}\n"
  ],
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    },
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
