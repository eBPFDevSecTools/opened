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
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "map_lookup_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "map_update_elem",
          "Input Params": [
            "{Type: struct map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
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
  "File": "/home/palani/github/opened_extraction/examples/cilium/custom/bytecount.h",
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
    "sk_skb",
    "cgroup_sysctl",
    "kprobe",
    "perf_event",
    "xdp",
    "lwt_xmit",
    "tracepoint",
    "cgroup_device",
    "lwt_seg6local",
    "sock_ops",
    "socket_filter",
    "raw_tracepoint",
    "sched_act",
    "flow_dissector",
    "sk_msg",
    "cgroup_sock_addr",
    "lwt_out",
    "cgroup_sock",
    "sk_reuseport",
    "lwt_in",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "sched_cls"
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
