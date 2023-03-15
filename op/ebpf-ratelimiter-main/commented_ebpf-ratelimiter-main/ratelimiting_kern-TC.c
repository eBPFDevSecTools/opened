#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
struct bpf_map_def SEC ("maps")
rl_config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof (uint32_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1,
};
struct bpf_map_def SEC ("maps")
rl_window_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint64_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 100,
};
struct bpf_map_def SEC ("maps")
rl_recv_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint64_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1
};
struct bpf_map_def SEC ("maps")
rl_drop_count_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint64_t),
    .value_size = sizeof (uint64_t),
    .max_entries = 1
};
struct bpf_map_def SEC ("maps")
rl_ports_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof (uint16_t),
    .value_size = sizeof (uint8_t),
    .max_entries = 50
};
struct bpf_map_def SEC ("maps")
xdp_rl_ingress_next_prog = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof (int),
    .value_size = sizeof (int),
    .max_entries = 1
};

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
    },
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ],
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
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_update"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
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
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 64,
  "endLine": 128,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/transformed/ratelimiting_kern-TC.c",
  "funcName": "_xdp_ratelimit",
  "updateMaps": [
    " rl_window_map"
  ],
  "readMaps": [
    " rl_window_map",
    " rl_ports_map",
    "  rl_window_map",
    " rl_config_map",
    " rl_recv_count_map",
    " rl_drop_count_map"
  ],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_ktime_get_ns",
    "TC_ACT_SHOT",
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "TC_ACT_OK"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "static __always_inline int _xdp_ratelimit (struct  __sk_buff *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ethhdr *eth = data;\n",
    "    if (data + sizeof (*eth) > data_end)\n",
    "        return TC_ACT_SHOT;\n",
    "    uint16_t eth_type = ctx->protocol;\n",
    "    if (ntohs (eth_type) != ETH_P_IP) {\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    struct iphdr *iph = data + sizeof (struct ethhdr);\n",
    "    if (iph + 1 > data_end)\n",
    "        return TC_ACT_OK;\n",
    "    if (iph->protocol != IPPROTO_TCP)\n",
    "        return TC_ACT_OK;\n",
    "    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);\n",
    "    if (tcph + 1 > data_end)\n",
    "        return TC_ACT_OK;\n",
    "    if (!(tcph->syn & TCP_FLAGS))\n",
    "        return TC_ACT_OK;\n",
    "    if (tcph->ack & TCP_FLAGS)\n",
    "        return TC_ACT_OK;\n",
    "    uint16_t dstport = bpf_ntohs (tcph -> dest);\n",
    "    if (!bpf_map_lookup_elem (&rl_ports_map, &dstport))\n",
    "        return TC_ACT_OK;\n",
    "    uint64_t rkey = 0;\n",
    "    uint64_t *rate = bpf_map_lookup_elem (&rl_config_map, &rkey);\n",
    "    if (!rate)\n",
    "        return TC_ACT_OK;\n",
    "    uint64_t tnow = bpf_ktime_get_ns ();\n",
    "    uint64_t NANO = 1000000000;\n",
    "    uint64_t MULTIPLIER = 100;\n",
    "    uint64_t cw_key = tnow / NANO * NANO;\n",
    "    uint64_t pw_key = cw_key - NANO;\n",
    "    uint64_t *pw_count = bpf_map_lookup_elem (&rl_window_map, &pw_key);\n",
    "    uint32_t *cw_count = bpf_map_lookup_elem (&rl_window_map, &cw_key);\n",
    "    uint64_t *in_count = bpf_map_lookup_elem (&rl_recv_count_map, &rkey);\n",
    "    uint64_t *drop_count = bpf_map_lookup_elem (&rl_drop_count_map, &rkey);\n",
    "    if (!in_count || !drop_count)\n",
    "        return TC_ACT_OK;\n",
    "    (*in_count)++;\n",
    "    if (!cw_count) {\n",
    "        uint64_t init_count = 0;\n",
    "        bpf_map_update_elem (&rl_window_map, &cw_key, &init_count, BPF_NOEXIST);\n",
    "        cw_count = bpf_map_lookup_elem (& rl_window_map, & cw_key);\n",
    "        if (!cw_count)\n",
    "            return TC_ACT_OK;\n",
    "    }\n",
    "    if (!pw_count) {\n",
    "        if (*cw_count >= *rate) {\n",
    "            (*drop_count)++;\n",
    "            return TC_ACT_SHOT;\n",
    "        }\n",
    "        (*cw_count)++;\n",
    "        return TC_ACT_OK;\n",
    "    }\n",
    "    uint64_t pw_weight = MULTIPLIER - (uint64_t) (((tnow - cw_key) * MULTIPLIER) / NANO);\n",
    "    uint64_t total_count = (uint64_t) ((pw_weight *(* pw_count)) +(*cw_count) * MULTIPLIER);\n",
    "    if (total_count > ((*rate) * MULTIPLIER)) {\n",
    "        (*drop_count)++;\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    (*cw_count)++;\n",
    "    return TC_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "ntohs",
    "bpf_ntohs",
    "bpf_printk"
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
static __always_inline int _xdp_ratelimit (struct __sk_buff *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth = data;
    if (data + sizeof (*eth) > data_end)
        return TC_ACT_SHOT;
    uint16_t eth_type = ctx->protocol;
    if (ntohs (eth_type) != ETH_P_IP) {
        return TC_ACT_OK;
    }
    struct iphdr *iph = data + sizeof (struct ethhdr);
    if (iph + 1 > data_end)
        return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);
    if (tcph + 1 > data_end)
        return TC_ACT_OK;
    if (!(tcph->syn & TCP_FLAGS))
        return TC_ACT_OK;
    if (tcph->ack & TCP_FLAGS)
        return TC_ACT_OK;
    uint16_t dstport = bpf_ntohs (tcph->dest);
    if (!bpf_map_lookup_elem (&rl_ports_map, &dstport))
        return TC_ACT_OK;
    uint64_t rkey = 0;
    uint64_t *rate = bpf_map_lookup_elem (&rl_config_map, &rkey);
    if (!rate)
        return TC_ACT_OK;
    uint64_t tnow = bpf_ktime_get_ns ();
    uint64_t NANO = 1000000000;
    uint64_t MULTIPLIER = 100;
    uint64_t cw_key = tnow / NANO * NANO;
    uint64_t pw_key = cw_key - NANO;
    uint64_t *pw_count = bpf_map_lookup_elem (&rl_window_map, &pw_key);
    uint32_t *cw_count = bpf_map_lookup_elem (&rl_window_map, &cw_key);
    uint64_t *in_count = bpf_map_lookup_elem (&rl_recv_count_map, &rkey);
    uint64_t *drop_count = bpf_map_lookup_elem (&rl_drop_count_map, &rkey);
    if (!in_count || !drop_count)
        return TC_ACT_OK;
    (*in_count)++;
    if (!cw_count) {
        uint64_t init_count = 0;
        bpf_map_update_elem (& rl_window_map, & cw_key, & init_count, BPF_NOEXIST);
        cw_count = bpf_map_lookup_elem (&rl_window_map, &cw_key);
        if (!cw_count)
            return TC_ACT_OK;
    }
    if (!pw_count) {
        if (*cw_count >= *rate) {
            (*drop_count)++;
            return TC_ACT_SHOT;
        }
        (*cw_count)++;
        return TC_ACT_OK;
    }
    uint64_t pw_weight = MULTIPLIER - (uint64_t) (((tnow - cw_key) * MULTIPLIER) / NANO);
    uint64_t total_count = (uint64_t) ((pw_weight * (*pw_count)) + (*cw_count) * MULTIPLIER);
    if (total_count > ((*rate) * MULTIPLIER)) {
        (*drop_count)++;
        return TC_ACT_SHOT;
    }
    (*cw_count)++;
    return TC_ACT_OK;
}

SEC ("xdp_ratelimiting")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_OK",
          "Return": 0,
          "Description": "will terminate the packet processing pipeline and allows the packet to proceed. Pass the skb onwards either to upper layers of the stack on ingress or down to the networking device driver for transmission on egress, respectively. TC_ACT_OK sets skb->tc_index based on the classid the tc BPF program set. The latter is set out of the tc BPF program itself through skb->tc_classid from the BPF context.",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 131,
  "endLine": 138,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/transformed/ratelimiting_kern-TC.c",
  "funcName": "_xdp_ratelimiting",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "int",
  "helper": [
    "TC_ACT_OK",
    "TC_ACT_SHOT",
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sched_cls"
  ],
  "source": [
    "int _xdp_ratelimiting (struct  __sk_buff *ctx)\n",
    "{\n",
    "    int rc = _xdp_ratelimit (ctx);\n",
    "    if (rc == TC_ACT_SHOT) {\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    bpf_tail_call (ctx, &xdp_rl_ingress_next_prog, 0);\n",
    "    return TC_ACT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_printk",
    "_xdp_ratelimit"
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
int _xdp_ratelimiting (struct __sk_buff *ctx) {
    int rc = _xdp_ratelimit (ctx);
    if (rc == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    bpf_tail_call (ctx, & xdp_rl_ingress_next_prog, 0);
    return TC_ACT_OK;
}

char _license [] SEC ("license") = "Dual BSD/GPL";
