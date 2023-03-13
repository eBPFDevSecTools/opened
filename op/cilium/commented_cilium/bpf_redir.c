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

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 25,
  "endLine": 39,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c",
  "funcName": "sk_msg_extract4_key",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct sk_msg_md *msg",
    " struct sock_key *key"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "flow_dissector",
    "cgroup_sock",
    "socket_filter",
    "cgroup_sysctl",
    "kprobe",
    "raw_tracepoint",
    "perf_event",
    "lwt_xmit",
    "lwt_seg6local",
    "sock_ops",
    "lwt_out",
    "xdp",
    "cgroup_skb",
    "sk_reuseport",
    "cgroup_sock_addr",
    "cgroup_device",
    "sk_skb",
    "lwt_in",
    "raw_tracepoint_writable",
    "sched_act",
    "sched_cls",
    "tracepoint"
  ],
  "source": [
    "static __always_inline void sk_msg_extract4_key (const struct sk_msg_md *msg, struct sock_key *key)\n",
    "{\n",
    "    key->dip4 = msg->remote_ip4;\n",
    "    key->sip4 = msg->local_ip4;\n",
    "    key->family = ENDPOINT_KEY_IPV4;\n",
    "    key->sport = (bpf_ntohl (msg->local_port) >> 16);\n",
    "    key->dport = READ_ONCE (msg->remote_port) >> 16;\n",
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
static __always_inline void sk_msg_extract4_key(const struct sk_msg_md *msg,
						struct sock_key *key)
{
	key->dip4 = msg->remote_ip4;
	key->sip4 = msg->local_ip4;
	key->family = ENDPOINT_KEY_IPV4;

	key->sport = (bpf_ntohl(msg->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated.
	 */
	key->dport = READ_ONCE(msg->remote_port) >> 16;
}

__section("sk_msg")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 42,
  "endLine": 67,
  "File": "/home/sayandes/opened_extraction/examples/cilium/sockops/bpf_redir.c",
  "funcName": "bpf_redir_proxy",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct sk_msg_md *msg"
  ],
  "output": "int",
  "helper": [
    "msg_redirect_hash"
  ],
  "compatibleHookpoints": [
    "sk_msg"
  ],
  "source": [
    "int bpf_redir_proxy (struct sk_msg_md *msg)\n",
    "{\n",
    "    struct remote_endpoint_info *info;\n",
    "    __u64 flags = BPF_F_INGRESS;\n",
    "    struct sock_key key = {}\n",
    "    ;\n",
    "    __u32 dst_id = 0;\n",
    "    int verdict;\n",
    "    sk_msg_extract4_key (msg, &key);\n",
    "    info = lookup_ip4_remote_endpoint (key.dip4);\n",
    "    if (info != NULL && info->sec_label)\n",
    "        dst_id = info->sec_label;\n",
    "    else\n",
    "        dst_id = WORLD_ID;\n",
    "    verdict = policy_sk_egress (dst_id, key.sip4, (__u16) key.dport);\n",
    "    if (verdict >= 0)\n",
    "        msg_redirect_hash (msg, &SOCK_OPS_MAP, &key, flags);\n",
    "    return SK_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "lookup_ip4_remote_endpoint",
    "sk_msg_extract4_key",
    "policy_sk_egress"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": " Store infomations about destination id, dport and sport ip4 into message, flag set to be BPF_F_INGRESS ",
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
int bpf_redir_proxy(struct sk_msg_md *msg)
{
	struct remote_endpoint_info *info;
	__u64 flags = BPF_F_INGRESS;
	struct sock_key key = {};
	__u32 dst_id = 0;
	int verdict;

	sk_msg_extract4_key(msg, &key);

	/* Currently, pulling dstIP out of endpoint
	 * tables. This can be simplified by caching this information with the
	 * socket to avoid extra overhead. This would require the agent though
	 * to flush the sock ops map on policy changes.
	 */
	info = lookup_ip4_remote_endpoint(key.dip4);
	if (info != NULL && info->sec_label)
		dst_id = info->sec_label;
	else
		dst_id = WORLD_ID;

	verdict = policy_sk_egress(dst_id, key.sip4, (__u16)key.dport);
	if (verdict >= 0)
		msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
	return SK_PASS;
}

BPF_LICENSE("Dual BSD/GPL");
int _version __section("version") = 1;
