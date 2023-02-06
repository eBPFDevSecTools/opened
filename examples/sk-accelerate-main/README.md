# sk-accelerate

sk-accelerate is a CNI-agnostic optimization that uses sockops/sockmap to
accelerate TCP packets between communicating pods on the same host machine. By
avoiding traversing the Linux network stacks, it allows for more efficient
communication between a pair of local sockets. We support the following
scenarios:
- pod-to-pod (local)
- pod-to-service (local)
- ipv4/ipv6 dual-stack

It should run on any CNI. We have tested it with Flannel, Cilium, Calico on Kubernetes and Openshift. 

## Prereq

Need Linux kernel version >= 4.18

## Install

```
kubectl apply -f https://raw.githubusercontent.com/ebpf-networking/sk-accelerate/main/sockmap.yml
```

## Testing

## Uninstall

```
kubectl delete -f https://raw.githubusercontent.com/ebpf-networking/sk-accelerate/main/sockmap.yml
```

# How it works

## Pod IP

eBPF supports hookpoints to cgroups, so when processes within a cgroup are
establishing TCP connections (also supports other types of networking events),
the attached eBPF code will get invoked. The specific events relevant to us are
`BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` and `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`,
corresponding to the events when TCP connections are actively or passively
established, respectively. When such events happen, we record the 2 socket
endpoints in a `BPF_MAP_TYPE_SOCKHASH` eBPF map.

Subsequently, when network packets within the monitored cgroup are sent,
another eBPF program will use the 5-tuple information of the packets to check
if the communicating ends are both local by checking the
`BPF_MAP_TYPE_SOCKHASH` map. If so, the packets will then be directly delivered
to the receiving socket without traversing any additional kernel code paths,
thus, significantly reducing processing overhead and improving performance.

## Service IP

Socket acceleration between 2 pods via their pod IPs is straight forward as we
only need to check if the communicating ends both have entries in the eBPF map.
However, in the real world, pod IPs are rarely used directly. Within a cluster,
pods will more likely communicate with other pods via their service IPs.
Service IPs once allocated are always stable. This allows their backend pods to
fail and restart (and get assigned with a new pod IP), without impacting pods
that try to communicate with them if service IPs were used.

In a simple example, a client pod `A` talks to a server pod `B` via a service
`B'`.  From `A`'s perspective, it is talking to `B'` and does not know about
`B`. When `A` sends a packet to `B'`, it will eventually get rewritten (e.g.,
by Kubeproxy) so the destination IP will change to `B`. When `B` receives the
packet, it knows that the packet originates from `A`. This creates an asymmetry
as `B` knows about `A`, but `A` only knows about `B'` but not `B`. This
asymmetry also exists in the eBPF map and will prevent socket acceleration from
happening as `B'` is deemed not local, even though both `A` and `B` are running
on the same worker node.

One solution is to translate service IPs to pod IPs before writing to the eBPF
map. Likewise, when packets are sent, we will also translate from service IPs
to their pod IPs before checking the eBPF map.  In the example above, instead
of having `A->B'` and `B->A` in the eBPF map, we will have `A->B` and `B->A`,
which restores symmetry again and will now accelerate as intended. 

However, one potential issue is since service IPs could have multiple backend
pods, we will need to create some extra entries in the eBPF map. Let's assume
`B'` has 2 backend pods `B` and `C`. When `A` talks to `B` via `B'`, we will
add both `A->B` and `A->C` into the eBPF map. The extra `A->C` entry should
remain dormant and not used, unless `A` talks to both `B` and `C` via `B'`,
which should also work as both `A<->B` and `A<->C` will get accelerated.

In the above example, we assume `A`, `B` and `C` are co-located on the same
worker node. What happens if `C` is not local? In this case, it should also
work as the `A->C` entry is only added to the eBPF map on one worker node, but
the `C->A` entry is added on another worker node. So, we will not accelerate
`A<->C`, which is as intended.

A potential issue with this approach is a service could have many endpoints,
e.g., 50-100. This could require a lot of dormant entries getting written to
the eBPF map (thus increasing its memory foodprint). A way to optimize this is
to query `conntrack` so we know exactly which endpoint was chosen in which
connection and only writing a single entry into the eBPF map.
