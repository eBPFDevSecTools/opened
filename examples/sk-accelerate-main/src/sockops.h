/*
 * Most of this code is from reading and understanding the code here:
 * - https://github.com/cilium/cilium/tree/master/bpf/sockops
 * - https://github.com/cyralinc/os-eBPF
 * - https://github.com/zachidan/ebpf-sockops
 *
 */

#ifndef READ_ONCE
#define READ_ONCE(x)        (*(volatile typeof(x) *)&x)
#endif

// Hash key to the sock_ops_map. Supports both ipv4 and ipv6
struct sock_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } src;
    union {
        __u32 ip4;
        __u32 ip6[4];
    } dst;
    __u8 family;
    __u8 pad1;
    __u16 pad2;
    // this padding required for 64bit alignment
    // else ebpf kernel verifier rejects loading
    // of the program
    __u32 pad3;
    __u32 sport;
    __u32 dport;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);   // dst IP
    __type(value, int);             // data
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps") ;

// Hash key to the services_map. Supports both ipv4 and ipv6
/*
struct service_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct service_value {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct service_key);        // dst service IP
    __type(value, struct service_value);    // service namespace + name
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} services_map SEC(".maps");
*/

// Endpoints IPs are kept in a map of hash maps. The key to the outer map is the 
// namespace+name pair. The key to the inner maps are the pod IPs, and the 
// value is a static number 0.
/*
struct endpoints_ips_outer_key {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct endpoints_ips_inner_key {
    union {
        __u32 ip4;
        __u32 ip6[4];
    } ip;
} __attribute__((packed));

struct endpoints_ips_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct endpoints_ips_inner_key);
    __type(value, __u32);
} endpoints_ips_inner_map SEC(".maps");

// BPF_MAP_TYPE_HASH_OF_MAPS was introduced in kernel 4.12, so any recent kernel should support it
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_ips_outer_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct endpoints_ips_inner_map);
} endpoints_ips_map SEC(".maps");
*/

// Endpoints Ports are kept in a map of hash maps. The key to the outer map is the 
// namespace+name pair. The key to the inner maps are the ports, and the 
// value is a static number 0.
/*
struct endpoints_ports_outer_key {
    char namespace[128];
    char name[128];
} __attribute__((packed));

struct endpoints_ports_inner_key {
    int port;
} __attribute__((packed));

struct endpoints_ports_inner_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, struct endpoints_ports_inner_key);
    __type(value, __u32);
} endpoints_ports_inner_map SEC(".maps");

// BPF_MAP_TYPE_HASH_OF_MAPS was introduced in kernel 4.12, so any recent kernel should support it
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_ports_outer_key);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct endpoints_ports_inner_map);
} endpoints_ports_map SEC(".maps");
*/

// Endpoints-to-Service is a hashmap. The key is <pod ip>:<pod port>, and the value is <service ip>:<service port>
// As the name suggests, it creates a map entry for each endpoint pod ip:port to service ip:port pair
struct endpoints_to_service_key {
    __u32 ip;
    __u32 port;
} __attribute__((packed));

struct endpoints_to_service_value {
    __u32 ip;
    __u32 port;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct endpoints_to_service_key);
    __type(value, struct endpoints_to_service_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} endpoints_to_service_map SEC(".maps");

// Sock-Ops-Aux is a hashmap. The key and value are both sock_key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct sock_key);
    __type(value, struct sock_key);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_aux_map SEC(".maps");

// Here is an example of how endpoints_to_service_map and sock_ops_aux_map are used to support service IPs
// pod 1 IP: 1
// pod 2 IP: 2
// service IP to pod 2: 9
//
// When pod 1 makes a tcp connection to pod 2 via its service IP, the following entries are added to sock_ops_map:
//
// -----------------
// | key   | value |
// -----------------
// | 1->9  |  sk1  |
// | 2->1  |  sk2  |
// -----------------
//
// Without any additional ebpf maps, we cannot accelerate the tcp connection betwee pod 1 and pod 2 since the lookup of
// the keys '9->1' and '1->2' will fail. This is where the other ebpf maps come in. A K8s custom controller is created
// to monitor for endpoints, and it will put the following entries in endpoints_to_service_map:
//
// -----------------
// | key   | value |
// -----------------
// |  2    |   9   |
// -----------------
//
// At the tcp connection time, when the source ip/port matches an entry in the above map, it is possible that the connection
// was made through a service IP, e.g., when '2->1' connection is made, we will see that '2' is in the endpoints_to_service_map.
// At this time, we will create a few additional entries in the sock_ops_aux_map as follows:
//
// -----------------
// | key   | value |
// -----------------
// | 1->2  | 1->9  |
// | 9->1  | 2->1  |
// -----------------
//
// The map complements the sock_ops_map, so during sendmsg phase, we first check in this map before checking the sock_ops_map.
// The previously failing lookups of '9->1' and '1->2' can now be found in this map, and we will use the correponding values
// of these entries (i.e., '1->9' and '2->1') to do further lookup in sock_ops_map, which will now succeed.
