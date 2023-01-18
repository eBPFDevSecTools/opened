#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <uapi/linux/bpf.h>

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in tcp_hdr() -> skb_transport_header().
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    // unstable API. verify logic in ip_hdr() -> skb_network_header().
    return (struct iphdr *)(skb->head + skb->network_header);
}

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
