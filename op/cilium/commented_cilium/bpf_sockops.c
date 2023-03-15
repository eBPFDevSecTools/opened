// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>

#include <linux/if_ether.h>

#define SKIP_CALLS_MAP 1
#define SKIP_POLICY_MAP 1

#define SOCKMAP 1

#include "../lib/common.h"
#include "../lib/maps.h"
#include "../lib/lb.h"
#include "../lib/eps.h"
#include "../lib/events.h"
#include "../lib/policy.h"

#include "bpf_sockops.h"

#ifdef ENABLE_IPV4
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 26,
  "endLine": 40,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "sk_extract4_key",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of Cilium */"
    },
    {
      "start_line": 34,
      "end_line": 38,
      "text": "/* clang-7.1 or higher seems to think it can do a 16-bit read here\n\t * which unfortunately most kernels (as of October 2019) do not\n\t * support, which leads to verifier failures. Insert a READ_ONCE\n\t * to make sure that a 32-bit read followed by shift is generated.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_sock_ops *ops",
    " struct sock_key *key"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline void sk_extract4_key (const struct bpf_sock_ops *ops, struct sock_key *key)\n",
    "{\n",
    "    key->dip4 = ops->remote_ip4;\n",
    "    key->sip4 = ops->local_ip4;\n",
    "    key->family = ENDPOINT_KEY_IPV4;\n",
    "    key->sport = (bpf_ntohl (ops->local_port) >> 16);\n",
    "    key->dport = READ_ONCE (ops->remote_port) >> 16;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohl",
    "READ_ONCE"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " set the sport and dport of the input key with 32 bits local port and remote port (ip4)  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
static __always_inline void sk_extract4_key(const struct bpf_sock_ops *ops,
					    struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = ENDPOINT_KEY_IPV4;

	key->sport = (bpf_ntohl(ops->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated.
	 */
	key->dport = READ_ONCE(ops->remote_port) >> 16;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 42,
  "endLine": 48,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "sk_lb4_key",
  "developer_inline_comments": [
    {
      "start_line": 45,
      "end_line": 45,
      "text": "/* SK MSG is always egress, so use daddr */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct lb4_key *lb4",
    " const struct sock_key *key"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static __always_inline void sk_lb4_key (struct lb4_key *lb4, const struct sock_key *key)\n",
    "{\n",
    "    lb4->address = key->dip4;\n",
    "    lb4->dport = (__u16) key->dport;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {
      "description": " copy address and dport of lb4 from socket key ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
static __always_inline void sk_lb4_key(struct lb4_key *lb4,
					  const struct sock_key *key)
{
	/* SK MSG is always egress, so use daddr */
	lb4->address = key->dip4;
	lb4->dport = (__u16)key->dport;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 50,
  "endLine": 53,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "redirect_to_proxy",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int verdict"
  ],
  "output": "static__always_inlinebool",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline bool redirect_to_proxy (int verdict)\n",
    "{\n",
    "    return verdict > 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "is_defined"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " check if verdict is larger than 0  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
static __always_inline bool redirect_to_proxy(int verdict)
{
	return verdict > 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 55,
  "endLine": 118,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "bpf_sock_ops_ipv4",
  "developer_inline_comments": [
    {
      "start_line": 66,
      "end_line": 68,
      "text": "/* If endpoint a service use L4/L3 stack for now. These can be\n\t * pulled in as needed.\n\t */"
    },
    {
      "start_line": 74,
      "end_line": 74,
      "text": "/* Policy lookup required to learn proxy port */"
    },
    {
      "start_line": 98,
      "end_line": 105,
      "text": "/* Lookup IPv4 address, this will return a match if:\n\t * - The destination IP address belongs to the local endpoint manage\n\t *   by Cilium.\n\t * - The destination IP address is an IP address associated with the\n\t *   host itself.\n\t * Then because these are local IPs that have passed LB/Policy/NAT\n\t * blocks redirect directly to socket.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "sock_hash_update"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static inline void bpf_sock_ops_ipv4 (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    struct lb4_key lb4_key = {}\n",
    "    ;\n",
    "    __u32 dip4, dport, dst_id = 0;\n",
    "    struct endpoint_info *exists;\n",
    "    struct lb4_service *svc;\n",
    "    struct sock_key key = {}\n",
    "    ;\n",
    "    int verdict;\n",
    "    sk_extract4_key (skops, &key);\n",
    "    sk_lb4_key (&lb4_key, &key);\n",
    "    svc = lb4_lookup_service (& lb4_key, true);\n",
    "    if (svc)\n",
    "        return;\n",
    "    if (1) {\n",
    "        struct remote_endpoint_info *info;\n",
    "        info = lookup_ip4_remote_endpoint (key.dip4);\n",
    "        if (info != NULL && info->sec_label)\n",
    "            dst_id = info->sec_label;\n",
    "        else\n",
    "            dst_id = WORLD_ID;\n",
    "    }\n",
    "    verdict = policy_sk_egress (dst_id, key.sip4, (__u16) key.dport);\n",
    "    if (redirect_to_proxy (verdict)) {\n",
    "        __be32 host_ip = IPV4_GATEWAY;\n",
    "        key.dip4 = key.sip4;\n",
    "        key.dport = key.sport;\n",
    "        key.sip4 = host_ip;\n",
    "        key.sport = verdict;\n",
    "        sock_hash_update (skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);\n",
    "        return;\n",
    "    }\n",
    "    exists = __lookup_ip4_endpoint (key.dip4);\n",
    "    if (!exists)\n",
    "        return;\n",
    "    dip4 = key.dip4;\n",
    "    dport = key.dport;\n",
    "    key.dip4 = key.sip4;\n",
    "    key.dport = key.sport;\n",
    "    key.sip4 = dip4;\n",
    "    key.sport = dport;\n",
    "    sock_hash_update (skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);\n",
    "}\n"
  ],
  "called_function_list": [
    "sk_lb4_key",
    "policy_sk_egress",
    "redirect_to_proxy",
    "__lookup_ip4_endpoint",
    "sk_extract4_key",
    "lb4_lookup_service",
    "lookup_ip4_remote_endpoint"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " update the destination and source port, ip to the skops with respect to whther  the packet is redirect to proxy port (or we say whether verdict is larger than 0) ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct lb4_key lb4_key = {};
	__u32 dip4, dport, dst_id = 0;
	struct endpoint_info *exists;
	struct lb4_service *svc;
	struct sock_key key = {};
	int verdict;

	sk_extract4_key(skops, &key);

	/* If endpoint a service use L4/L3 stack for now. These can be
	 * pulled in as needed.
	 */
	sk_lb4_key(&lb4_key, &key);
	svc = lb4_lookup_service(&lb4_key, true);
	if (svc)
		return;

	/* Policy lookup required to learn proxy port */
	if (1) {
		struct remote_endpoint_info *info;

		info = lookup_ip4_remote_endpoint(key.dip4);
		if (info != NULL && info->sec_label)
			dst_id = info->sec_label;
		else
			dst_id = WORLD_ID;
	}

	verdict = policy_sk_egress(dst_id, key.sip4, (__u16)key.dport);
	if (redirect_to_proxy(verdict)) {
		__be32 host_ip = IPV4_GATEWAY;

		key.dip4 = key.sip4;
		key.dport = key.sport;
		key.sip4 = host_ip;
		key.sport = verdict;

		sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
		return;
	}

	/* Lookup IPv4 address, this will return a match if:
	 * - The destination IP address belongs to the local endpoint manage
	 *   by Cilium.
	 * - The destination IP address is an IP address associated with the
	 *   host itself.
	 * Then because these are local IPs that have passed LB/Policy/NAT
	 * blocks redirect directly to socket.
	 */
	exists = __lookup_ip4_endpoint(key.dip4);
	if (!exists)
		return;

	dip4 = key.dip4;
	dport = key.dport;
	key.dip4 = key.sip4;
	key.dport = key.sport;
	key.sip4 = dip4;
	key.sport = dport;

	sock_hash_update(skops, &SOCK_OPS_MAP, &key, BPF_NOEXIST);
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 122,
  "endLine": 126,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "bpf_sock_ops_ipv6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "static inline void bpf_sock_ops_ipv6 (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    if (skops->remote_ip4)\n",
    "        bpf_sock_ops_ipv4 (skops);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_sock_ops_ipv4"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " update the destination and source port, ip to the skops with respect to whther  the packet is redirect to proxy port (or we say whether verdict is larger than 0) same as bpf_sock_ops_ipv4 but adapt for ipv6 ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
static inline void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
	if (skops->remote_ip4)
		bpf_sock_ops_ipv4(skops);
}
#endif /* ENABLE_IPV6 */

__section("sockops")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 130,
  "endLine": 154,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_sockops.c",
  "funcName": "bpf_sockmap",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "cgroup_sock",
    "cgroup_sock_addr",
    "lwt_xmit",
    "sk_skb",
    "sock_ops",
    "sk_reuseport",
    "perf_event",
    "cgroup_skb",
    "tracepoint",
    "lwt_seg6local",
    "cgroup_sysctl",
    "socket_filter",
    "flow_dissector",
    "sched_cls",
    "lwt_in",
    "lwt_out",
    "sk_msg",
    "cgroup_device",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_act",
    "xdp",
    "raw_tracepoint"
  ],
  "source": [
    "int bpf_sockmap (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    __u32 family, op;\n",
    "    family = skops->family;\n",
    "    op = skops->op;\n",
    "    switch (op) {\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB :\n",
    "\n",
    "#ifdef ENABLE_IPV6\n",
    "        if (family == AF_INET6)\n",
    "            bpf_sock_ops_ipv6 (skops);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifdef ENABLE_IPV4\n",
    "        if (family == AF_INET)\n",
    "            bpf_sock_ops_ipv4 (skops);\n",
    "\n",
    "#endif\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_sock_ops_ipv4",
    "bpf_sock_ops_ipv6"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " calling bpf_sock_ops_ipv4 or bpf_sock_ops_ipv6 according to the family ip version  ",
      "author": "Shun Zhang",
      "authorEmail": "shunz@bu.edu",
      "date": "2023-02-24"
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
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
#ifdef ENABLE_IPV6
		if (family == AF_INET6)
			bpf_sock_ops_ipv6(skops);
#endif
#ifdef ENABLE_IPV4
		if (family == AF_INET)
			bpf_sock_ops_ipv4(skops);
#endif
		break;
	default:
		break;
	}

	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
int _version __section("version") = 1;
