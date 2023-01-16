/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} bytecount_map __section_maps_btf;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "map_lookup_elem": [
      {
        "opVar": "\tbytecount ",
        "inpVar": [
          " &bytecount_map",
          " &identity"
        ]
      }
    ],
    "map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "\telse\t\t\t\t&bytecount_map",
          " &identity",
          " &len",
          " BPF_ANY"
        ]
      }
    ]
  },
  "startLine": 11,
  "endLine": 24,
  "File": "/home/sayandes/opened_extraction/examples/cilium/custom/bytecount.h",
  "funcName": "custom_prog",
  "updateMaps": [
    " bytecount_map"
  ],
  "readMaps": [
    "  bytecount_map"
  ],
  "input": [
    "const struct  __ctx_buff *ctx",
    " __u32 identity"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "map_update_elem",
    "map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "flow_dissector",
    "sk_skb",
    "raw_tracepoint_writable",
    "socket_filter",
    "sched_act",
    "sk_reuseport",
    "xdp",
    "sk_msg",
    "lwt_in",
    "cgroup_skb",
    "cgroup_sock",
    "lwt_xmit",
    "cgroup_device",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "lwt_seg6local",
    "cgroup_sock_addr",
    "tracepoint",
    "raw_tracepoint",
    "sched_cls",
    "lwt_out"
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
static __always_inline
void custom_prog(const struct __ctx_buff *ctx, __u32 identity)
{
	__u64 len, *bytecount;

	len = ctx_full_len(ctx);

	bytecount = map_lookup_elem(&bytecount_map, &identity);
	if (bytecount)
		__sync_fetch_and_add(bytecount, len);
	else
		/* No entry for endpoint in hashmap, attempt to create one */
		map_update_elem(&bytecount_map, &identity, &len, BPF_ANY);
}
