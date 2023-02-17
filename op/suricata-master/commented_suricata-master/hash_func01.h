/* SPDX-License-Identifier: LGPL-2.1
 *
 * Based on Paul Hsieh's (LGPG 2.1) hash function
 * From: http://www.azillionmonkeys.com/qed/hash.html
 */

#define get16bits(d) (*((const __u16 *) (d)))

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 55,
  "File": "/home/sayandes/opened_extraction/examples/suricata-master/ebpf/hash_func01.h",
  "funcName": "SuperFastHash",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *data",
    " int len",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sysctl",
    "lwt_xmit",
    "perf_event",
    "socket_filter",
    "flow_dissector",
    "sched_act",
    "lwt_out",
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_seg6local",
    "sk_skb",
    "sk_reuseport",
    "sk_msg",
    "lwt_in",
    "sched_cls",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "cgroup_device",
    "kprobe",
    "tracepoint",
    "sock_ops",
    "xdp",
    "raw_tracepoint"
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
static __always_inline
__u32 SuperFastHash (const char *data, int len, __u32 initval) {
	__u32 hash = initval;
	__u32 tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
#pragma clang loop unroll(full)
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (__u16);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= ((signed char)data[sizeof (__u16)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*data;
                hash ^= hash << 10;
                hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}
