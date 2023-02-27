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
          ]
        }
      ]
    },
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
    "bpf_map_lookup_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "    if ! &rl_ports_map",
          " &dstport        return TC_ACT_OK"
        ]
      },
      {
        "opVar": "    uint64_t *rate ",
        "inpVar": [
          "  &rl_config_map",
          " &rkey"
        ]
      },
      {
        "opVar": "    uint64_t *pw_count ",
        "inpVar": [
          "  &rl_window_map",
          " &pw_key"
        ]
      },
      {
        "opVar": "    uint32_t *cw_count ",
        "inpVar": [
          "  &rl_window_map",
          " &cw_key"
        ]
      },
      {
        "opVar": "    uint64_t *in_count ",
        "inpVar": [
          "  &rl_recv_count_map",
          " &rkey"
        ]
      },
      {
        "opVar": "    uint64_t *drop_count ",
        "inpVar": [
          "  &rl_drop_count_map",
          " &rkey"
        ]
      },
      {
        "opVar": "        cw_count ",
        "inpVar": [
          "  &rl_window_map",
          " &cw_key"
        ]
      }
    ],
    "bpf_ktime_get_ns": [
      {
        "opVar": "    uint64_t tnow ",
        "inpVar": [
          "  "
        ]
      }
    ],
    "bpf_map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "         & rl_window_map",
          " & cw_key",
          " & init_count",
          " BPF_NOEXIST"
        ]
      }
    ]
  },
  "startLine": 64,
  "endLine": 128,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/transformed/ratelimiting_kern-TC.c",
  "funcName": "_xdp_ratelimit",
  "updateMaps": [
    " rl_window_map"
  ],
  "readMaps": [
    " rl_window_map",
    " rl_recv_count_map",
    "  rl_window_map",
    " rl_drop_count_map",
    " rl_config_map",
    " rl_ports_map"
  ],
  "input": [
    "struct  __sk_buff *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_map_update_elem",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
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
  "humanFuncDescription": [
    {
      "description": "This function implements a TCP connection rate limiter. Takes in input a packet in struct xdp_mp * ctx form. It first checks if input is a valid ethernet packet. It ignores other than ethernet packets, other than ip packets, other than tcp packets. If the packet is a valid tcp packet, it check if the packet is a TCP syn packet as it performs connection rate limiting it ignores packets other than tcp syn packets and even tcp syn ack packets. If the packet is a TCP SYN hence connection establishment packet, the code reads a map rl_config_map with key set to number 0 and receives the allowed rate of connections configured from the userspace if the map read fails, the function returns TC_ACT_OK else it continues execution. Next it checks which time window the packet corresponds to, a window is essentially a 1 second sliding window calculated by calling bpf_ktime_get_ns and getting the current time. Current time is used to calculate current window cw_key and previous window(current - 1 s) is used to calculate previous window pw_key. The function then performs a bunch of map reads, 1) rl_window_map twice with keys cw_key and pw_key which gives the cw_count and pw_count essentially current window packet count and previous window packet count. 2) rl_recv_count_map with key set to number 0 which tracks number of incommming connections 3) rl_drop_count_map with key set to number 0 which tracks number of dropped connections. If this is the first packet in this window then the function updates the map rl_window_map with key cw_key and value 0 and sets the cw_count to 0. If this is a new connection and no previous connection were present then the rate limiter allows connection if cw_count < rate and returns TC_ACT_OK else it drops the connection and returns TC_ACT_SHOT. If there had been previous connections then it calculates the number of connections accepted in last 1 sec from current time, if the total connections are higher than allowed rate, it drops the connection and returns TC_ACT_SHOT else it allows the connection and returns TC_ACT_OK. The function also updates the current window count and drop count before returning."
      ,
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
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
  "capabilities": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "NA",
        "inpVar": [
          "         ctx",
          " & xdp_rl_ingress_next_prog",
          " 0"
        ]
      }
    ]
  },
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
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "perf_event",
    "sched_act",
    "flow_dissector",
    "sched_cls",
    "tracepoint",
    "cgroup_sock_addr",
    "sk_skb",
    "sock_ops",
    "lwt_seg6local",
    "lwt_xmit",
    "sk_msg",
    "sk_reuseport",
    "kprobe",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "xdp",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_in"
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
  "humanFuncDescription": [
    {
      "description": "This is a wrapper function which calls the base function _xdp_ratelimit with the same arument passed to it and returns its value",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "2023-02-20"
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
int _xdp_ratelimiting (struct __sk_buff *ctx) {
    int rc = _xdp_ratelimit (ctx);
    if (rc == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    bpf_tail_call (ctx, & xdp_rl_ingress_next_prog, 0);
    return TC_ACT_OK;
}

char _license [] SEC ("license") = "Dual BSD/GPL";
