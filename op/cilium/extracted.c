/* SPDX-License-Identifier: GPL-2.0 */
#define RECORD_FLOW_INFO
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include <node_config.h>
#include <netdev_config.h>
#ifndef COMMON_H_OPENED_FRAMEWORK
#define COMMON_H_OPENED_FRAMEWORK
#include "common.h"
#endif 

#ifndef LB_H_OPENED_FRAMEWORK
#define LB_H_OPENED_FRAMEWORK
#include "lb.h"
#endif 

#ifndef EPS_H_OPENED_FRAMEWORK
#define EPS_H_OPENED_FRAMEWORK
#include "eps.h"
#endif 

#ifndef IDENTITY_H_OPENED_FRAMEWORK
#define IDENTITY_H_OPENED_FRAMEWORK
#include "identity.h"
#endif 

#ifndef METRICS_H_OPENED_FRAMEWORK
#define METRICS_H_OPENED_FRAMEWORK
#include "metrics.h"
#endif 

#ifndef NAT_46X64_H_OPENED_FRAMEWORK
#define NAT_46X64_H_OPENED_FRAMEWORK
#include "nat_46x64.h"
#endif 

#ifndef COMMON_H_OPENED_FRAMEWORK
#define COMMON_H_OPENED_FRAMEWORK
#include "common.h"
#endif 

#ifndef SKB_H_OPENED_FRAMEWORK
#define SKB_H_OPENED_FRAMEWORK
//#include "skb.h"
#endif 

#ifndef NODE_CONFIG_H_OPENED_FRAMEWORK
#define NODE_CONFIG_H_OPENED_FRAMEWORK
#include "node_config.h"
#endif 

#ifndef CONNTRACK_H_OPENED_FRAMEWORK
#define CONNTRACK_H_OPENED_FRAMEWORK
#include "conntrack.h"
#endif 

#ifndef CONNTRACK_MAP_H_OPENED_FRAMEWORK
#define CONNTRACK_MAP_H_OPENED_FRAMEWORK
#include "conntrack_map.h"
#endif 

#include <bpf/ctx/skb.h>
#include <ep_config.h>
#include <bpf/verifier.h>
#include <linux/icmpv6.h>
#ifndef TAILCALL_H_OPENED_FRAMEWORK
#define TAILCALL_H_OPENED_FRAMEWORK
#include "tailcall.h"
#endif 

#ifndef CONFIG_H_OPENED_FRAMEWORK
#define CONFIG_H_OPENED_FRAMEWORK
#include "config.h"
#endif 

#ifndef MAPS_H_OPENED_FRAMEWORK
#define MAPS_H_OPENED_FRAMEWORK
#include "maps.h"
#endif 

#ifndef ARP_H_OPENED_FRAMEWORK
#define ARP_H_OPENED_FRAMEWORK
#include "arp.h"
#endif 

#ifndef EDT_H_OPENED_FRAMEWORK
#define EDT_H_OPENED_FRAMEWORK
#include "edt.h"
#endif 

#ifndef QM_H_OPENED_FRAMEWORK
#define QM_H_OPENED_FRAMEWORK
#include "qm.h"
#endif 

#ifndef IPV6_H_OPENED_FRAMEWORK
#define IPV6_H_OPENED_FRAMEWORK
#include "ipv6.h"
#endif 

#ifndef IPV4_H_OPENED_FRAMEWORK
#define IPV4_H_OPENED_FRAMEWORK
#include "ipv4.h"
#endif 

#ifndef ICMP6_H_OPENED_FRAMEWORK
#define ICMP6_H_OPENED_FRAMEWORK
#include "icmp6.h"
#endif 

#ifndef ETH_H_OPENED_FRAMEWORK
#define ETH_H_OPENED_FRAMEWORK
#include "eth.h"
#endif 

#ifndef DBG_H_OPENED_FRAMEWORK
#define DBG_H_OPENED_FRAMEWORK
#include "dbg.h"
#endif 

#ifndef L3_H_OPENED_FRAMEWORK
#define L3_H_OPENED_FRAMEWORK
#include "l3.h"
#endif 

#ifndef LXC_H_OPENED_FRAMEWORK
#define LXC_H_OPENED_FRAMEWORK
#include "lxc.h"
#endif 

#ifndef POLICY_H_OPENED_FRAMEWORK
#define POLICY_H_OPENED_FRAMEWORK
#include "policy.h"
#endif 

#ifndef DROP_H_OPENED_FRAMEWORK
#define DROP_H_OPENED_FRAMEWORK
#include "drop.h"
#endif 

#ifndef TRACE_H_OPENED_FRAMEWORK
#define TRACE_H_OPENED_FRAMEWORK
#include "trace.h"
#endif 

#ifndef CSUM_H_OPENED_FRAMEWORK
#define CSUM_H_OPENED_FRAMEWORK
#include "csum.h"
#endif 

#ifndef EGRESS_POLICIES_H_OPENED_FRAMEWORK
#define EGRESS_POLICIES_H_OPENED_FRAMEWORK
#include "egress_policies.h"
#endif 

#ifndef ENCAP_H_OPENED_FRAMEWORK
#define ENCAP_H_OPENED_FRAMEWORK
#include "encap.h"
#endif 

#ifndef NAT_H_OPENED_FRAMEWORK
#define NAT_H_OPENED_FRAMEWORK
#include "nat.h"
#endif 

#ifndef FIB_H_OPENED_FRAMEWORK
#define FIB_H_OPENED_FRAMEWORK
#include "fib.h"
#endif 

#ifndef NODEPORT_H_OPENED_FRAMEWORK
#define NODEPORT_H_OPENED_FRAMEWORK
#include "nodeport.h"
#endif 

#ifndef POLICY_LOG_H_OPENED_FRAMEWORK
#define POLICY_LOG_H_OPENED_FRAMEWORK
#include "policy_log.h"
#endif 

/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 121 endLine: 131
 */ 
static __always_inline __maybe_unused
bool sock_is_health_check(struct bpf_sock_addr *ctx __maybe_unused)
{
#ifdef ENABLE_HEALTH_CHECK
	int val;

	if (!get_socket_opt(ctx, SOL_SOCKET, SO_MARK, &val, sizeof(val)))
		return val == MARK_MAGIC_HEALTH;
#endif
	return false;
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 58 endLine: 62
 */ 
static __always_inline __maybe_unused
void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}
#ifdef  ENABLE_L7_LB
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 460 endLine: 476
 */ 
static __always_inline int
__sock4_health_fwd(struct bpf_sock_addr *ctx __maybe_unused)
{
	int ret = lb_skip_l4_dnat() ? SYS_PROCEED : SYS_REJECT;
#ifdef ENABLE_HEALTH_CHECK
	__sock_cookie key = get_socket_cookie(ctx);
	struct lb4_health *val = NULL;

	if (!lb_skip_l4_dnat())
		val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
	if (val) {
		ctx_set_port(ctx, val->peer.port);
		ret = SYS_PROCEED;
	}
#endif /* ENABLE_HEALTH_CHECK */
	return ret;
}
#endif 
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 64 endLine: 72
 */ 
static __always_inline __maybe_unused bool task_in_extended_hostns(void)
{
#ifdef ENABLE_MKE
	/* Extension for non-Cilium managed containers on MKE. */
	return get_cgroup_classid() == MKE_HOST;
#else
	return false;
#endif
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 74 endLine: 89
 */ 
static __always_inline __maybe_unused bool
ctx_in_hostns(void *ctx __maybe_unused, __net_cookie *cookie)
{
#ifdef BPF_HAVE_NETNS_COOKIE
	__net_cookie own_cookie = get_netns_cookie(ctx);

	if (cookie)
		*cookie = own_cookie;
	return own_cookie == HOST_NETNS_COOKIE ||
	       task_in_extended_hostns();
#else
	if (cookie)
		*cookie = 0;
	return true;
#endif
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 42 endLine: 48
 */ 
static __always_inline __maybe_unused __be16
ctx_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;

	return (__be16)dport;
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 140 endLine: 156
 */ 
static __always_inline __maybe_unused
bool sock_proto_enabled(__u32 proto)
{
	switch (proto) {
#ifdef ENABLE_SOCKET_LB_TCP
	case IPPROTO_TCP:
		return true;
#endif /* ENABLE_SOCKET_LB_TCP */
#ifdef ENABLE_SOCKET_LB_UDP
	case IPPROTO_UDPLITE:
	case IPPROTO_UDP:
		return true;
#endif /* ENABLE_SOCKET_LB_UDP */
	default:
		return false;
	}
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 27 endLine: 31
 */ 
static __always_inline __maybe_unused bool is_v4_loopback(__be32 daddr)
{
	/* Check for 127.0.0.0/8 range, RFC3330. */
	return (daddr & bpf_htonl(0x7f000000)) == bpf_htonl(0x7f000000);
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 202 endLine: 218
 */ 
static __always_inline bool
sock4_skip_xlate(struct lb4_service *svc, __be32 address)
{
	if (lb4_to_lb6_service(svc))
		return true;
	if (lb4_svc_is_external_ip(svc) ||
	    (lb4_svc_is_hostport(svc) && !is_v4_loopback(address))) {
		struct remote_endpoint_info *info;

		info = ipcache_lookup4(&IPCACHE_MAP, address,
				       V4_CACHE_KEY_LEN);
		if (info == NULL || info->sec_label != HOST_ID)
			return true;
	}

	return false;
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 91 endLine: 119
 */ 
static __always_inline __maybe_unused
__sock_cookie sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef BPF_HAVE_SOCKET_COOKIE
	/* prandom() breaks down on UDP, hence preference is on
	 * socket cookie as built-in selector. On older kernels,
	 * get_socket_cookie() provides a unique per netns cookie
	 * for the life-time of the socket. For newer kernels this
	 * is fixed to be a unique system _global_ cookie. Older
	 * kernels could have a cookie collision when two pods with
	 * different netns talk to same service backend, but that
	 * is fine since we always reverse translate to the same
	 * service IP/port pair. The only case that could happen
	 * for older kernels is that we have a cookie collision
	 * where one pod talks to the service IP/port and the
	 * other pod talks to that same specific backend IP/port
	 * directly _w/o_ going over service IP/port. Then the
	 * reverse sock addr is translated to the service IP/port.
	 * With a global socket cookie this collision cannot take
	 * place. There, only the even more unlikely case could
	 * happen where the same UDP socket talks first to the
	 * service and then to the same selected backend IP/port
	 * directly which can be considered negligible.
	 */
	return get_socket_cookie(ctx);
#else
	return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#endif
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 133 endLine: 138
 */ 
static __always_inline __maybe_unused
__u64 sock_select_slot(struct bpf_sock_addr *ctx)
{
	return ctx->protocol == IPPROTO_TCP ?
	       get_prandom_u32() : sock_local_cookie(ctx);
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 293 endLine: 321
 */ 
static __always_inline bool
sock4_skip_xlate_if_same_netns(struct bpf_sock_addr *ctx __maybe_unused,
			       const struct lb4_backend *backend __maybe_unused)
{
#ifdef BPF_HAVE_SOCKET_LOOKUP
	struct bpf_sock_tuple tuple = {
		.ipv4.daddr = backend->address,
		.ipv4.dport = backend->port,
	};
	struct bpf_sock *sk = NULL;

	switch (ctx->protocol) {
	case IPPROTO_TCP:
		sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	case IPPROTO_UDP:
		sk = sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
				   BPF_F_CURRENT_NETNS, 0);
		break;
	}

	if (sk) {
		sk_release(sk);
		return true;
	}
#endif /* BPF_HAVE_SOCKET_LOOKUP */
	return false;
}
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 323 endLine: 458
 */ 
static __always_inline int __sock4_xlate_fwd(struct bpf_sock_addr *ctx,
					     struct bpf_sock_addr *ctx_full,
					     const bool udp_only)
{
	union lb4_affinity_client_id id;
	const bool in_hostns = ctx_in_hostns(ctx_full, &id.client_cookie);
	struct lb4_backend *backend;
	struct lb4_service *svc;
	struct lb4_key key = {
		.address	= ctx->user_ip4,
		.dport		= ctx_dst_port(ctx),
	}, orig_key = key;
	struct lb4_service *backend_slot;
	bool backend_from_affinity = false;
	__u32 backend_id = 0;
#ifdef ENABLE_L7_LB
	struct lb4_backend l7backend;
#endif

	if (is_defined(ENABLE_SOCKET_LB_HOST_ONLY) && !in_hostns)
		return -ENXIO;

	if (!udp_only && !sock_proto_enabled(ctx->protocol))
		return -ENOTSUP;

	/* In case a direct match fails, we try to look-up surrogate
	 * service entries via wildcarded lookup for NodePort and
	 * HostPort services.
	 */
	svc = lb4_lookup_service(&key, true);
	if (!svc)
		svc = sock4_wildcard_lookup_full(&key, in_hostns);
	if (!svc)
		return -ENXIO;

	/* Do not perform service translation for external IPs
	 * that are not a local address because we don't want
	 * a k8s service to easily do MITM attacks for a public
	 * IP address. But do the service translation if the IP
	 * is from the host.
	 */
	if (sock4_skip_xlate(svc, orig_key.address))
		return -EPERM;

#ifdef ENABLE_L7_LB
	/* Do not perform service translation at socker layer for
	 * services with L7 load balancing as we need to postpone
	 * policy enforcement to take place after l7 load balancer and
	 * we can't currently do that from the socket layer.
	 */
	if (lb4_svc_is_l7loadbalancer(svc)) {
		/* TC level eBPF datapath does not handle node local traffic,
		 * but we need to redirect for L7 LB also in that case.
		 */
		if (is_defined(BPF_HAVE_NETNS_COOKIE) && in_hostns) {
			/* Use the L7 LB proxy port as a backend. Normally this
			 * would cause policy enforcement to be done before the
			 * L7 LB (which should not be done), but in this case
			 * (node-local nodeport) there is no policy enforcement
			 * anyway.
			 */
			l7backend.address = bpf_htonl(0x7f000001);
			l7backend.port = (__be16)svc->l7_lb_proxy_port;
			l7backend.proto = 0;
			l7backend.flags = 0;
			backend = &l7backend;
			goto out;
		}
		/* Let the TC level eBPF datapath redirect to L7 LB. */
		return 0;
	}
#endif /* ENABLE_L7_LB */

	if (lb4_svc_is_affinity(svc)) {
		/* Note, for newly created affinity entries there is a
		 * small race window. Two processes on two different
		 * CPUs but the same netns may select different backends
		 * for the same service:port. lb4_update_affinity_by_netns()
		 * below would then override the first created one if it
		 * didn't make it into the lookup yet for the other CPU.
		 */
		backend_id = lb4_affinity_backend_id_by_netns(svc, &id);
		backend_from_affinity = true;

		if (backend_id != 0) {
			backend = __lb4_lookup_backend(backend_id);
			if (!backend)
				/* Backend from the session affinity no longer
				 * exists, thus select a new one. Also, remove
				 * the affinity, so that if the svc doesn't have
				 * any backend, a subsequent request to the svc
				 * doesn't hit the reselection again.
				 */
				backend_id = 0;
		}
	}

	if (backend_id == 0) {
		backend_from_affinity = false;

		key.backend_slot = (sock_select_slot(ctx_full) % svc->count) + 1;
		backend_slot = __lb4_lookup_backend_slot(&key);
		if (!backend_slot) {
			update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND_SLOT);
			return -ENOENT;
		}

		backend_id = backend_slot->backend_id;
		backend = __lb4_lookup_backend(backend_id);
	}

	if (!backend) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_NO_BACKEND);
		return -ENOENT;
	}

	if (lb4_svc_is_localredirect(svc) &&
	    sock4_skip_xlate_if_same_netns(ctx_full, backend))
		return -ENXIO;

	if (lb4_svc_is_affinity(svc) && !backend_from_affinity)
		lb4_update_affinity_by_netns(svc, &id, backend_id);
#ifdef ENABLE_L7_LB
out:
#endif
	if (sock4_update_revnat(ctx_full, backend, &orig_key,
				svc->rev_nat_index) < 0) {
		update_metrics(0, METRIC_EGRESS, REASON_LB_REVNAT_UPDATE);
		return -ENOMEM;
	}

	ctx->user_ip4 = backend->address;
	ctx_set_port(ctx, backend->port);

	return 0;
}
#ifdef  ENABLE_L7_LB
/* Extracted from 
 /home/sayandes/opened_extraction/examples/cilium/bpf_sock.c 
 startLine: 479 endLine: 486
 */ 
int sock4_connect(struct bpf_sock_addr *ctx)
{
	if (sock_is_health_check(ctx))
		return __sock4_health_fwd(ctx);

	__sock4_xlate_fwd(ctx, ctx, false);
	return SYS_PROCEED;
}
#endif 
BPF_LICENSE("Dual BSD/GPL");
