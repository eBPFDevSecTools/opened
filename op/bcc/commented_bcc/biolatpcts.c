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
      "read_sys_info": [
        {
          "Description": "Return the time elapsed since system boot , in nanoseconds. ",
          "Return": "Current ktime.",
          "Return Type": "u64",
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
      "{\n \"opVar\": \"\\tdur \",\n \"inpVar\": [\n  \"  - rq->io_start_time_ns\"\n ]\n}"
    ]
  },
  "startLine": 8,
  "endLine": 29,
  "File": "/home/sayandes/opened_extraction/examples/bcc/biolatpcts.c",
  "Funcname": "RAW_TRACEPOINT_PROBE",
  "Update_maps": [
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "block_rq_complete"
  ],
  "Output": "NA",
  "Helper": "bpf_ktime_get_ns,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
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
