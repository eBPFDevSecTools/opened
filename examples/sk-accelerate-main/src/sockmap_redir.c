#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "sockops.h"


/* extract the key that identifies the destination socket in the sock_ops_map */
static inline
void sk_msg_extract4_key(struct sk_msg_md *msg,
    struct sock_key *key)
{
    key->src.ip4 = msg->remote_ip4;
    key->dst.ip4 = msg->local_ip4;
    key->family = 2;

    key->dport = (bpf_htonl(msg->local_port) >> 16);
    key->sport = READ_ONCE(msg->remote_port) >> 16;
}

static inline
void sk_msg_extract6_key(struct sk_msg_md *msg,
    struct sock_key *key)
{
    //__builtin_memset((void*)&key->dst.ip6, 0, 32);
    //__builtin_memset((void*)&key->src.ip6, 0, 32);
    //__builtin_memcpy((void*)&key->src.ip6, (void*)&msg->remote_ip6, sizeof(struct in6_addr));
    //__builtin_memcpy((void*)&key->dst.ip6, (void*)&msg->local_ip6, sizeof(struct in6_addr));
    key->src.ip6[0] = msg->remote_ip6[0];
    key->src.ip6[1] = msg->remote_ip6[1];
    key->src.ip6[2] = msg->remote_ip6[2];
    key->src.ip6[3] = msg->remote_ip6[3];
    key->dst.ip6[0] = msg->local_ip6[0];
    key->dst.ip6[1] = msg->local_ip6[1];
    key->dst.ip6[2] = msg->local_ip6[2];
    key->dst.ip6[3] = msg->local_ip6[3];
    key->family = 10;

    key->dport = (bpf_htonl(msg->local_port) >> 16);
    key->sport = READ_ONCE(msg->remote_port) >> 16;
}

SEC("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct sock_key key = {};
    if (msg->family == 2)
        sk_msg_extract4_key(msg, &key);
    else if (msg->family == 10) {
        if (msg->remote_ip4)
            sk_msg_extract4_key(msg, &key);
        else
            sk_msg_extract6_key(msg, &key);
    }
    else
        return SK_PASS;

    struct sock_key *aux_key;

    aux_key = bpf_map_lookup_elem(&sock_ops_aux_map, &key);
    if (aux_key) {
        //bpf_printk("*");
        bpf_msg_redirect_hash(msg, &sock_ops_map, aux_key, BPF_F_INGRESS);
    }
    else {
        bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    }
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
