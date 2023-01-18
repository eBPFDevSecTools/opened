#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <uapi/linux/bpf.h>

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 12,
  "File": "/root/examples/bcc/nflatency.c",
  "funcName": "*skb_to_tcphdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct sk_buff *skb"
  ],
  "output": "staticstructtcphdr",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 18,
  "File": "/root/examples/bcc/nflatency.c",
  "funcName": "*skb_to_iphdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct sk_buff *skb"
  ],
  "output": "staticinlinestructiphdr",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 20,
  "endLine": 24,
  "File": "/root/examples/bcc/nflatency.c",
  "funcName": "*skb_to_ip6hdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct sk_buff *skb"
  ],
  "output": "staticinlinestructipv6hdr",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
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
static inline struct ipv6hdr *skb_to_ip6hdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct ipv6hdr *)(skb->head + skb->network_header);
}

// for correlating between kprobe and kretprobe
struct start_data {
    u8 hook;
    u8 pf; // netfilter protocol
    u8 tcp_state;
    u64 ts;
};
BPF_PERCPU_ARRAY(sts, struct start_data, 1);

// the histogram keys
typedef struct nf_lat_key {
    u8 proto; // see netfilter.h
    u8 hook;
    u8 tcp_state;
} nf_lat_key_t;

typedef struct hist_key {
    nf_lat_key_t key;
    u64 slot;
} hist_key_t;
BPF_HISTOGRAM(dist, hist_key_t);


/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
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
    "bpf_ktime_get_ns": [
      {
        "opVar": "    data.ts ",
        "inpVar": [
          " "
        ]
      }
    ]
  },
  "startLine": 49,
  "endLine": 88,
  "File": "/root/examples/bcc/nflatency.c",
  "funcName": "kprobe__nf_hook_slow",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " struct sk_buff *skb",
    " struct nf_hook_state *state"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_cls",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act"
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
int kprobe__nf_hook_slow(struct pt_regs *ctx, struct sk_buff *skb, struct nf_hook_state *state) {
    struct start_data data = {};
    data.ts = bpf_ktime_get_ns();
    data.hook = state->hook;
    data.pf = state->pf;

    COND

    u8 ip_proto;
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *ip = skb_to_iphdr(skb);
        ip_proto = ip->protocol;

    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip = skb_to_ip6hdr(skb);
        ip_proto = ip->nexthdr;
    }

    data.tcp_state = 0;
    if (ip_proto == 0x06) { //tcp
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        u8 tcpflags = ((u_int8_t *)tcp)[13];

        // FIN or RST
        if (((tcpflags & 1) + (tcpflags & 4)) > 0) {
            data.tcp_state = 3;
        }
        // SYN / SACK
        else if ((tcpflags & 0x02) > 0) {
            data.tcp_state = 1;
            if ((tcpflags & 16) > 0) { // ACK
                data.tcp_state = 2;
            }
        }
    }

    u32 idx = 0;
    sts.update(&idx, &data);
    return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
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
    "bpf_ktime_get_ns": [
      {
        "opVar": "        s->ts ",
        "inpVar": [
          "  - s->ts"
        ]
      }
    ]
  },
  "startLine": 90,
  "endLine": 111,
  "File": "/root/examples/bcc/nflatency.c",
  "funcName": "kretprobe__nf_hook_slow",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_cls",
    "xdp",
    "lwt_seg6local",
    "cgroup_sock",
    "sk_reuseport",
    "perf_event",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "lwt_out",
    "socket_filter",
    "raw_tracepoint",
    "sk_msg",
    "kprobe",
    "flow_dissector",
    "cgroup_skb",
    "sk_skb",
    "lwt_in",
    "tracepoint",
    "cgroup_sock_addr",
    "sched_act"
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
int kretprobe__nf_hook_slow(struct pt_regs *ctx) {
    u32 idx = 0;
    struct start_data *s;
    s = sts.lookup(&idx);
    if (!s || s->ts == 0) {
        return 0;
    }

    s->ts = bpf_ktime_get_ns() - s->ts;

    hist_key_t key = {};
    key.key.hook = s->hook;
    key.key.proto = s->pf;
    key.key.tcp_state = s->tcp_state;
    key.slot = bpf_log2l(s->ts / FACTOR );
    dist.increment(key);

    s->ts = 0;
    sts.update(&idx, s);

    return 0;
}
