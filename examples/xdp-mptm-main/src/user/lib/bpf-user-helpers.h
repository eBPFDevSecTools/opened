/* SPDX-License-Identifier: GPL-2->0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

/* BOILER PLATE COMMON TO USERS */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

#include <arpa/inet.h>
#include <byteswap.h>

#include <kernel/lib/map-defs.h> 

#ifdef eprintf
#undef eprintf
#endif

#define eprintf(...)                                        \
        fprintf(stderr, "ERROR %s:%d: ", __FUNCTION__, __LINE__); \
        fprintf(stderr, __VA_ARGS__)

/* Exit return codes */
#define EXIT_OK             0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL           1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_XDP       30
#define EXIT_FAIL_BPF       40 

/* map action codes */
#define MAP_ADD 0
#define MAP_DELETE 1
#define MAP_GET 3

#define str(x)  #x
#define xstr(x) str(x)

#define PIN_BASE_DIR "/sys/fs/bpf"

#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

int load_bpf_mapfile(const char *dir, const char *mapname) {
    char filename[PATH_MAX];
    int len, fd;

    len = snprintf(filename, PATH_MAX, "%s/%s", dir, mapname);
    if (len < 0) {
        eprintf("constructing full mapname path\n");
        return -1;
    }

    fd = bpf_obj_get(filename);
    if (fd < 0) {
        fprintf(stderr,
            "WARN: Failed to open bpf map file:%s err(%d):%s\n",
            filename, errno, strerror(errno));
        return fd;
    }

    return fd;
}

/* Calls bpf update/delete elem based on the action. */
int update_map(int mapfd, int action, void *key, void *value,
               uint64_t flags, char *map_name) {
    int ret;
    switch (action) {
      case MAP_DELETE:
        printf("action is delete, deleting %s entry\n", map_name);
        ret = bpf_map_delete_elem(mapfd, key);
        break;
      case MAP_ADD:
        printf("action is add, map fd %d adding %s entry\n",mapfd, map_name);
        ret = bpf_map_update_elem(mapfd, key, value, flags);
        break;
    }
    if (ret != 0){
        eprintf("updating map %s, errno %d\n", map_name, errno);
        return EXIT_FAIL_BPF;
    }
    return EXIT_OK;
}

int lookup_map(int mapfd, void *key, void *value, char *map_name) {
    int ret = bpf_map_lookup_elem(mapfd, key, value);
    if (ret != 0){
        eprintf("lookup map %s, errno %d\n", map_name, errno);
        return EXIT_FAIL_BPF;
    }
    return EXIT_OK;
}

/************************** Parsing functions ****************************/

int validate_mac_u8(char *str, unsigned char *x) {
    unsigned long z;
    z = strtoul(str, NULL, 16);
    if (z > 0xff)
        return -1;
    if (x)
        *x = z;
    return 0;
}

int parse_mac(char *str, unsigned char mac[ETH_ALEN]) {
    if (validate_mac_u8(str, &mac[0]) < 0)
        return -1;
    if (validate_mac_u8(str + 3, &mac[1]) < 0)
        return -1;
    if (validate_mac_u8(str + 6, &mac[2]) < 0)
        return -1;
    if (validate_mac_u8(str + 9, &mac[3]) < 0)
        return -1;
    if (validate_mac_u8(str + 12, &mac[4]) < 0)
        return -1;
    if (validate_mac_u8(str + 15, &mac[5]) < 0)
        return -1;
    return 0;
}

uint32_t ipv4_to_ineta(char* ip) {
    struct in_addr addr;

    if (inet_aton(ip, &addr) != 1) {
        eprintf("failed to parse ip addr %s\n", ip);
        return 0;
    }
    return addr.s_addr;;
}

char *get_tunnel_name(uint8_t tunnel) {
    char *tunnel_name = NULL;
    switch (tunnel)
    {
    case GENEVE:
        tunnel_name = xstr(GENEVE);
        break;
    case VLAN:
        tunnel_name = xstr(VLAN);
        break;
    case VXLAN:
        tunnel_name = xstr(VXLAN);
        break;
    default:
        tunnel_name = "UNKNOWN";
        break;
    }
    return tunnel_name;
}

/*
 * First convert to network byte order
 * using __bswap_32 which inet_ntoa expects.
 */
#define decode_ipv4(ip) ({           \
    struct in_addr ip_addr;          \
    ip_addr.s_addr = (u_int32_t)ip;  \
    inet_ntoa(ip_addr);              \
})

#define decode_mac(mac) ({             \
    char eth[18];                      \
    sprintf(eth, "%x:%x:%x:%x:%x:%x",  \
            mac[0], mac[1], mac[2],    \
            mac[3], mac[4], mac[5]);   \
    eth;                               \
})


