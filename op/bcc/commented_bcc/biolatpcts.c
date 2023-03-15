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
          "Project": "bcc",
          "FunctionName": "bpf_ktime_get_ns",
          "Return Type": "u64",
          "Description": "u64 bpf_ktime_get_ns(void) Return: u64 number of nanoseconds. Starts at system boot time but stops during suspend. Examples in situ: \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code search /tools ",
          "Return": "u64 number of nanoseconds",
          "Input Prameters": [],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/bcc/biolatpcts.c",
  "funcName": "RAW_TRACEPOINT_PROBE",
  "developer_inline_comments": [],
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
    "sk_skb",
    "sched_act",
    "socket_filter",
    "cgroup_sock_addr",
    "lwt_xmit",
    "lwt_out",
    "raw_tracepoint",
    "lwt_seg6local",
    "raw_tracepoint_writable",
    "sk_msg",
    "cgroup_skb",
    "xdp",
    "tracepoint",
    "cgroup_sock",
    "sk_reuseport",
    "sock_ops",
    "perf_event",
    "lwt_in",
    "kprobe",
    "flow_dissector",
    "sched_cls"
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
  "called_function_list": [
    "div_u64",
    "min_t",
    "increment"
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
