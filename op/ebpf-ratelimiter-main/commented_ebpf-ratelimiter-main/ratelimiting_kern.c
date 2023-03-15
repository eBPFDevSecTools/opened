// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* Ratelimit incoming TCP connections using XDP */

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
#include <iproute2/bpf_elf.h>


/* TCP flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#define PIN_GLOBAL_NS        2

/* Stores the ratelimit value(per second) */
//Move map defintions to newer format 
struct bpf_elf_map rl_config_map __section("maps") = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.size_key       = sizeof(uint32_t),
	.size_value     = sizeof(uint64_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem     = 1,
};


/* Maintains the timestamp of a window and the total number of
 * connections received in that window(window = 1 sec interval) */
struct bpf_elf_map SEC("maps") rl_window_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem	= 100,
};

/* Maintains the total number of connections received(TCP-SYNs)
 * Used only for metrics visibility */
struct bpf_elf_map SEC("maps") rl_recv_count_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem	= 1
	
};

/* Maintains the total number of connections dropped as the ratelimit is hit
 * Used only for metrics visibility */
struct bpf_elf_map SEC("maps") rl_drop_count_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(uint64_t),
	.size_value	= sizeof(uint64_t),
	.pinning        = PIN_GLOBAL_NS,
	.max_elem	= 1
};

/* Maintains the ports to be ratelimited */
struct bpf_elf_map SEC("maps") rl_ports_map = {
        .type           = BPF_MAP_TYPE_HASH,
        .size_key       = sizeof(uint16_t),
        .size_value     = sizeof(uint8_t),
	 .pinning        = PIN_GLOBAL_NS,
        .max_elem    = 50
};



/* TODO Use atomics or spin locks where naive increments are used depending
 * on the accuracy tests and then do a tradeoff.
 * With 10k connections/sec tests, the error rate is < 3%. */
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
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
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
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
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
    }
  ],
  "helperCallParams": {},
  "startLine": 100,
  "endLine": 276,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_kern.c",
  "funcName": "_xdp_ratelimit",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// Copyright Contributors to the L3AF Project."
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)"
    },
    {
      "start_line": 4,
      "end_line": 4,
      "text": "/* Ratelimit incoming TCP connections using XDP */"
    },
    {
      "start_line": 19,
      "end_line": 19,
      "text": "/* TCP flags */"
    },
    {
      "start_line": 44,
      "end_line": 44,
      "text": "/* Stores the ratelimit value(per second) */"
    },
    {
      "start_line": 45,
      "end_line": 45,
      "text": "//Move map defintions to newer format "
    },
    {
      "start_line": 55,
      "end_line": 56,
      "text": "/* Maintains the timestamp of a window and the total number of\n * connections received in that window(window = 1 sec interval) */"
    },
    {
      "start_line": 65,
      "end_line": 66,
      "text": "/* Maintains the total number of connections received(TCP-SYNs)\n * Used only for metrics visibility */"
    },
    {
      "start_line": 76,
      "end_line": 77,
      "text": "/* Maintains the total number of connections dropped as the ratelimit is hit\n * Used only for metrics visibility */"
    },
    {
      "start_line": 86,
      "end_line": 86,
      "text": "/* Maintains the ports to be ratelimited */"
    },
    {
      "start_line": 97,
      "end_line": 99,
      "text": "/* TODO Use atomics or spin locks where naive increments are used depending\n * on the accuracy tests and then do a tradeoff.\n * With 10k connections/sec tests, the error rate is < 3%. */"
    },
    {
      "start_line": 107,
      "end_line": 107,
      "text": "/* Check if it is a valid ethernet packet */"
    },
    {
      "start_line": 111,
      "end_line": 111,
      "text": "/* Ignore other than ethernet packets */"
    },
    {
      "start_line": 117,
      "end_line": 117,
      "text": "/* Ignore other than IP packets */"
    },
    {
      "start_line": 122,
      "end_line": 122,
      "text": "/* Ignore other than TCP packets */"
    },
    {
      "start_line": 126,
      "end_line": 126,
      "text": "/* Check if its valid tcp packet */"
    },
    {
      "start_line": 134,
      "end_line": 134,
      "text": "/* Ignore other than TCP-SYN packets */"
    },
    {
      "start_line": 136,
      "end_line": 136,
      "text": "//bpf_printk(\"Ignoring %d \\n\",6);"
    },
    {
      "start_line": 141,
      "end_line": 141,
      "text": "/* Ignore TCP-SYN-ACK packets */"
    },
    {
      "start_line": 151,
      "end_line": 151,
      "text": "//bpf_printk(\"Check: rate  %d\\n\",rkey);"
    },
    {
      "start_line": 156,
      "end_line": 156,
      "text": "//bpf_printk(\"Set: rate %d\\n\",*rate);"
    },
    {
      "start_line": 159,
      "end_line": 159,
      "text": "//*rate = 5; //IRL Hard coding"
    },
    {
      "start_line": 162,
      "end_line": 162,
      "text": "/* Current time in monotonic clock */"
    },
    {
      "start_line": 165,
      "end_line": 165,
      "text": "/* Used for second to nanoseconds conversions and vice-versa */"
    },
    {
      "start_line": 168,
      "end_line": 171,
      "text": "/* Used for converting decimals points to percentages as decimal points\n     * are not recommended in the kernel.\n     * Ex: 0.3 would be converted as 30 with this multiplication factor to\n     * perform the calculations needed. */"
    },
    {
      "start_line": 174,
      "end_line": 177,
      "text": "/* Round off the current time to form the current window key.\n     * Ex: ts of the incoming connections from the time 16625000000000 till\n     * 166259999999 is rounded off to 166250000000000 to track the incoming\n     * connections received in that one second interval. */"
    },
    {
      "start_line": 182,
      "end_line": 182,
      "text": "/* Previous window is one second before the current window */"
    },
    {
      "start_line": 185,
      "end_line": 185,
      "text": "/* Number of incoming connections in the previous window(second) */"
    },
    {
      "start_line": 188,
      "end_line": 188,
      "text": "/* Number of incoming connections in the current window(second) */"
    },
    {
      "start_line": 191,
      "end_line": 191,
      "text": "/* Total number of incoming connections so far */"
    },
    {
      "start_line": 194,
      "end_line": 194,
      "text": "/* Total number of dropped connections so far */"
    },
    {
      "start_line": 197,
      "end_line": 198,
      "text": "/* Just make the verifier happy, it would never be the case in real as\n     * these two counters are initialised in the user space. */"
    },
    {
      "start_line": 203,
      "end_line": 206,
      "text": "/*\n    bpf_printk(\"cw_key %u\\n\",cw_key);\n    bpf_printk(\"pw_key %u\\n\",pw_key);\n*/"
    },
    {
      "start_line": 207,
      "end_line": 207,
      "text": "/* Increment the total number of incoming connections counter */"
    },
    {
      "start_line": 213,
      "end_line": 214,
      "text": "/* This is the first connection in the current window,\n         * initialize the current window counter. */"
    },
    {
      "start_line": 218,
      "end_line": 218,
      "text": "/* Just make the verifier happy */"
    },
    {
      "start_line": 224,
      "end_line": 226,
      "text": "/* This is the fresh start of system or there have been no\n         * connections in the last second, so make the decision purely based\n         * on the incoming connections in the current window. */"
    },
    {
      "start_line": 229,
      "end_line": 230,
      "text": "/* Connection count in the current window already exceeded the\n             * rate limit so drop this connection. */"
    },
    {
      "start_line": 235,
      "end_line": 235,
      "text": "/* Allow otherwise */"
    },
    {
      "start_line": 241,
      "end_line": 244,
      "text": "/* Calculate the number of connections accepted in last 1 sec from tnow *\n     * considering the connections accepted in previous window and          *\n     * current window based on what % of the sliding window(tnow - 1) falls *\n     * in previous window and what % of it is in the current window         */"
    },
    {
      "start_line": 254,
      "end_line": 254,
      "text": "//uint64_t temp = (*rate) * MULTIPLIER;"
    },
    {
      "start_line": 255,
      "end_line": 255,
      "text": "//uint64_t temp = 5;"
    },
    {
      "start_line": 257,
      "end_line": 257,
      "text": "//bpf_printk(\"temp: %d\\n\",temp);"
    },
    {
      "start_line": 259,
      "end_line": 259,
      "text": "//int c = (total_count > temp);"
    },
    {
      "start_line": 260,
      "end_line": 260,
      "text": "//bpf_printk(\"c: %d\\n\",c);"
    },
    {
      "start_line": 262,
      "end_line": 262,
      "text": "//if (c )"
    },
    {
      "start_line": 264,
      "end_line": 264,
      "text": "//if (total_count > ((*rate) * MULTIPLIER))"
    },
    {
      "start_line": 266,
      "end_line": 267,
      "text": "/* Connection count from tnow to (tnow-1) exceeded the rate limit,\n         * so drop this connection. */"
    },
    {
      "start_line": 272,
      "end_line": 272,
      "text": "/* Allow otherwise */"
    }
  ],
  "updateMaps": [
    " rl_window_map"
  ],
  "readMaps": [
    " rl_window_map",
    " rl_recv_count_map",
    "  rl_window_map",
    " rl_drop_count_map",
    " rl_config_map"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_map_lookup_elem",
    "XDP_DROP",
    "XDP_PASS",
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static __always_inline int _xdp_ratelimit (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ethhdr *eth = data;\n",
    "    if (data + sizeof (*eth) > data_end)\n",
    "        return XDP_DROP;\n",
    "    uint16_t eth_type = eth->h_proto;\n",
    "    if (ntohs (eth_type) != ETH_P_IP) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    struct iphdr *iph = data + sizeof (struct ethhdr);\n",
    "    if (iph + 1 > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (iph->protocol != IPPROTO_TCP)\n",
    "        return XDP_PASS;\n",
    "    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);\n",
    "    if (tcph + 1 > data_end)\n",
    "        return XDP_PASS;\n",
    "    bpf_printk (\"NEW: TCP Syn : %d\\n\", tcph->syn & TCP_FLAGS);\n",
    "    if (!(tcph->syn & TCP_FLAGS)) {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    if (tcph->ack & TCP_FLAGS)\n",
    "        return XDP_PASS;\n",
    "    uint16_t dstport = bpf_ntohs (tcph -> dest);\n",
    "    uint64_t rkey = 0;\n",
    "    uint64_t *rate = bpf_map_lookup_elem (&rl_config_map, &rkey);\n",
    "    if (!rate) {\n",
    "        bpf_printk (\"Return: rate %d\\n\", rkey);\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    else {\n",
    "    }\n",
    "    bpf_printk (\"Allowed connections rate: %d\\n\", *rate);\n",
    "    uint64_t tnow = bpf_ktime_get_ns ();\n",
    "    uint64_t NANO = 1000000000;\n",
    "    uint64_t MULTIPLIER = 100;\n",
    "    uint64_t cw_key = (tnow / NANO) * NANO;\n",
    "    uint64_t pw_key = cw_key - NANO;\n",
    "    uint64_t *pw_count = bpf_map_lookup_elem (&rl_window_map, &pw_key);\n",
    "    uint32_t *cw_count = bpf_map_lookup_elem (&rl_window_map, &cw_key);\n",
    "    uint64_t *in_count = bpf_map_lookup_elem (&rl_recv_count_map, &rkey);\n",
    "    uint64_t *drop_count = bpf_map_lookup_elem (&rl_drop_count_map, &rkey);\n",
    "    if (!in_count || !drop_count) {\n",
    "        bpf_printk (\"count null %d\\n\", rate);\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    (*in_count)++;\n",
    "    if (!cw_count) {\n",
    "        uint64_t init_count = 0;\n",
    "        bpf_map_update_elem (&rl_window_map, &cw_key, &init_count, BPF_NOEXIST);\n",
    "        cw_count = bpf_map_lookup_elem (& rl_window_map, & cw_key);\n",
    "        if (!cw_count)\n",
    "            return XDP_PASS;\n",
    "    }\n",
    "    if (!pw_count) {\n",
    "        if (*cw_count >= *rate) {\n",
    "            (*drop_count)++;\n",
    "            bpf_printk (\"DROPPING CONNECTION: CT  %d\\n\", *cw_count);\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        (*cw_count)++;\n",
    "        bpf_printk (\"ALLOWING CONNECTION: CT %d\\n\", *cw_count);\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    uint64_t pw_weight = MULTIPLIER - (uint64_t) (((tnow - cw_key) * MULTIPLIER) / NANO);\n",
    "    uint64_t total_count = (uint64_t) ((pw_weight *(* pw_count)) +(*cw_count) * MULTIPLIER);\n",
    "    bpf_printk (\"tot_ct : %d\\n\", total_count);\n",
    "    bpf_printk (\"cw1_ct : %d\\n\", *cw_count);\n",
    "    if (total_count > (*rate)) {\n",
    "        (*drop_count)++;\n",
    "        bpf_printk (\"DROPPING CONNECTION: CT  %d\\n\", *cw_count);\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    (*cw_count)++;\n",
    "    bpf_printk (\"ALLOWING CONNECTION: CT  %d\\n\", *cw_count);\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "ntohs",
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
static __always_inline int _xdp_ratelimit(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    /* Check if it is a valid ethernet packet */
    if (data + sizeof(*eth) > data_end)
        return XDP_DROP;

    /* Ignore other than ethernet packets */
    uint16_t eth_type = eth->h_proto;
    if (ntohs(eth_type) != ETH_P_IP) {
        return XDP_PASS;
    }

    /* Ignore other than IP packets */
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end)
        return XDP_PASS;

    /* Ignore other than TCP packets */
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Check if its valid tcp packet */
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if (tcph + 1 > data_end)
        return XDP_PASS;


    bpf_printk("NEW: TCP Syn : %d\n", tcph->syn & TCP_FLAGS);
      
    /* Ignore other than TCP-SYN packets */
    if (!(tcph->syn & TCP_FLAGS)){
      //bpf_printk("Ignoring %d \n",6);
        return XDP_PASS;
    }

       
    /* Ignore TCP-SYN-ACK packets */
    if (tcph->ack & TCP_FLAGS)
        return XDP_PASS;


    uint16_t dstport = bpf_ntohs(tcph->dest);

    
    uint64_t rkey = 0;
    uint64_t *rate = bpf_map_lookup_elem(&rl_config_map, &rkey);
    //bpf_printk("Check: rate  %d\n",rkey);
    if (!rate){
        bpf_printk("Return: rate %d\n",rkey);
	return XDP_PASS;
    } else {
      //bpf_printk("Set: rate %d\n",*rate);
    }

    //*rate = 5; //IRL Hard coding
    bpf_printk("Allowed connections rate: %d\n", *rate);

    /* Current time in monotonic clock */
    uint64_t tnow = bpf_ktime_get_ns();

    /* Used for second to nanoseconds conversions and vice-versa */
    uint64_t NANO = 1000000000;

    /* Used for converting decimals points to percentages as decimal points
     * are not recommended in the kernel.
     * Ex: 0.3 would be converted as 30 with this multiplication factor to
     * perform the calculations needed. */
    uint64_t MULTIPLIER = 100;

    /* Round off the current time to form the current window key.
     * Ex: ts of the incoming connections from the time 16625000000000 till
     * 166259999999 is rounded off to 166250000000000 to track the incoming
     * connections received in that one second interval. */
    
    uint64_t cw_key = (tnow / NANO)  * NANO;
    

    /* Previous window is one second before the current window */
    uint64_t pw_key = cw_key - NANO;

    /* Number of incoming connections in the previous window(second) */
    uint64_t *pw_count = bpf_map_lookup_elem(&rl_window_map, &pw_key);

    /* Number of incoming connections in the current window(second) */
    uint32_t *cw_count = bpf_map_lookup_elem(&rl_window_map, &cw_key);

    /* Total number of incoming connections so far */
    uint64_t *in_count = bpf_map_lookup_elem(&rl_recv_count_map, &rkey);

    /* Total number of dropped connections so far */
    uint64_t *drop_count = bpf_map_lookup_elem(&rl_drop_count_map, &rkey);

    /* Just make the verifier happy, it would never be the case in real as
     * these two counters are initialised in the user space. */
    if(!in_count || !drop_count){
      bpf_printk("count null %d\n",rate);
      return XDP_PASS;
    }
/*
    bpf_printk("cw_key %u\n",cw_key);
    bpf_printk("pw_key %u\n",pw_key);
*/
    /* Increment the total number of incoming connections counter */

    (*in_count)++;

    if (!cw_count)
    {
        /* This is the first connection in the current window,
         * initialize the current window counter. */
        uint64_t init_count = 0;
        bpf_map_update_elem(&rl_window_map, &cw_key, &init_count, BPF_NOEXIST);
        cw_count = bpf_map_lookup_elem(&rl_window_map, &cw_key);
        /* Just make the verifier happy */
        if (!cw_count)
            return XDP_PASS;
    }
    if (!pw_count)
    {
        /* This is the fresh start of system or there have been no
         * connections in the last second, so make the decision purely based
         * on the incoming connections in the current window. */
        if (*cw_count >= *rate)
        {
            /* Connection count in the current window already exceeded the
             * rate limit so drop this connection. */
            (*drop_count)++;
            bpf_printk("DROPPING CONNECTION: CT  %d\n",*cw_count);
            return XDP_DROP;
        }
        /* Allow otherwise */
        (*cw_count)++;
        bpf_printk("ALLOWING CONNECTION: CT %d\n",*cw_count);
        return XDP_PASS;
    }

    /* Calculate the number of connections accepted in last 1 sec from tnow *
     * considering the connections accepted in previous window and          *
     * current window based on what % of the sliding window(tnow - 1) falls *
     * in previous window and what % of it is in the current window         */
    uint64_t pw_weight = MULTIPLIER -
        (uint64_t)(((tnow - cw_key) * MULTIPLIER) / NANO);

    uint64_t total_count = (uint64_t)((pw_weight * (*pw_count)) +
        (*cw_count) * MULTIPLIER);

    bpf_printk("tot_ct : %d\n", total_count);
    bpf_printk("cw1_ct : %d\n", *cw_count);

    //uint64_t temp = (*rate) * MULTIPLIER;
    //uint64_t temp = 5;
    
    //bpf_printk("temp: %d\n",temp);

    //int c = (total_count > temp);
    //bpf_printk("c: %d\n",c);
    
    //if (c )
    if (total_count > (*rate))
      //if (total_count > ((*rate) * MULTIPLIER))
    {
        /* Connection count from tnow to (tnow-1) exceeded the rate limit,
         * so drop this connection. */
        (*drop_count)++;
        bpf_printk("DROPPING CONNECTION: CT  %d\n", *cw_count);
        return XDP_DROP;
    }
    /* Allow otherwise */
    (*cw_count)++;
    bpf_printk("ALLOWING CONNECTION: CT  %d\n",*cw_count);
    return XDP_PASS;
}

SEC("xdp_ratelimiting")
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
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
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
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 279,
  "endLine": 289,
  "File": "/home/sayandes/opened_extraction/examples/ebpf-ratelimiter-main/ratelimiting_kern.c",
  "funcName": "_xdp_ratelimiting",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "XDP_PASS",
    "XDP_DROP"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int _xdp_ratelimiting (struct xdp_md *ctx)\n",
    "{\n",
    "    bpf_printk (\"entered xdp_rate_limiter\\n\");\n",
    "    int rc = _xdp_ratelimit (ctx);\n",
    "    if (rc == XDP_DROP) {\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "_xdp_ratelimit",
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
int _xdp_ratelimiting(struct xdp_md *ctx)
{
    bpf_printk("entered xdp_rate_limiter\n");  
    int rc = _xdp_ratelimit(ctx);

   if (rc == XDP_DROP) {
      return XDP_DROP;
   }

   return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
