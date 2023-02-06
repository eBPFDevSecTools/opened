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
int _xdp_ratelimiting (struct __sk_buff *ctx) {
    int rc = _xdp_ratelimit (ctx);
    if (rc == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    bpf_tail_call (ctx, & xdp_rl_ingress_next_prog, 0);
    return TC_ACT_OK;
}

char _license [] SEC ("license") = "Dual BSD/GPL";
