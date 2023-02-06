/* SPDX-License-Identifier: GPL-2->0
 *  
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <kernel/lib/map-defs.h>
#include <user/lib/bpf-user-helpers.h>

// TODO: make sure this can be overridden using env or argument
#define TUNNEL_INFO_MAP     "mptm_tunnel_info_map"
#define REDIRECT_IF_DEVMAP  "mptm_redirect_if_devmap"

#define TUNNEL_INFO_KEY(mptm)          __get_tunnel_info_map_key(mptm, false)
#define TUNNEL_INFO_KEY_INV(mptm)      __get_tunnel_info_map_key(mptm, true)

typedef struct {
    /* Arguments for the tunnels */
    int action;
    u_int64_t vlid;
    u_int16_t flags;
    u_int16_t source_port;
    u_int32_t vpeer_iface;
    u_int32_t veth_iface;
    u_int32_t eth0_iface;
    char source_addr[16];
    char dest_addr[16];
    char source_mac[18];
    char outer_dest_mac[18];
    char inner_dest_mac[18];
    u_int8_t debug;
    u_int8_t tunnel;
    u_int8_t redirect;
    char inner_src_addr[16];
    char inner_dst_addr[16];

    /* Map file descriptors and keys used for the maps */
    int tunnel_map_fd;
    int redirect_if_devmap_fd;
    tunnel_map_key_t *tun_key;
} mptm_info;

void  print_usage() {
  printf("\nPlease see usage:\n"
         "\t -t/--tunnel <1 for VLAN / 3 for GENEVE>\n"
         "\t tunnel VLAN:-\n"
         "\t\t -v/--vlid <vlan id>\n"
         "\t tunnel GENEVE:-\n"
         "\t\t -v/--vlid <vlan id>\n"
         "\t\t -p/--source_port <port-num>\n"
         "\t\t -I/--ingress_iface <dev-num>\n"
         "\t\t -s/--source_ip <source-ip e.g. 10.1.1.1>\n"
         "\t\t -S/--source_mac <source-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t\t -d/--dest_ip <dest-ip e.g. 10.1.1.1>\n"
         "\t\t -D/--dest_mac <dest-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t\t -M/--inner_dest_mac <inner-dest-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t\t -x/--inner_src_ip <inner-src-ip e.g. 10.250.1.1>\n"
         "\t\t -x/--inner_dst_ip <inner-dst-ip e.g. 10.250.1.2>\n"
         "\t common options:-\n"
         "\t\t -r/--redirect <1 or 0>\n"
         "\t\t -L/--vpeer_iface <dev-num>\n"
         "\t\t -M/--veth_iface <dev-num>\n"
         "\t\t -N/--eth0_iface <dev-num>\n"
         "\t\t -f/--flags <0>\n"
         "\t\t -l/--enable_logs <1 or 0>\n"
         "\t\t -a/--action [ADD/DEL/GET] rule\n"
        );
}

static const struct option long_options[] = {
        {"help",           no_argument,       NULL, 'h'},
        {"action",         required_argument, NULL, 'a'},
        {"tunnel",         required_argument, NULL, 't'},
        {"vlid",           required_argument, NULL, 'v'}, //"tunnel vlan id of <connection>", "<vlid>", true},
        {"flags",          required_argument, NULL, 'f'}, //"tunnel flags of <connection>", "<flags>", true},
        {"source_port",    required_argument, NULL, 'p'}, //"Source Port of <connection>", "<port>", true},
        {"vpeer_iface",    required_argument, NULL, 'X'}, //"Iface id vpeer device <dev>[eth0]", "<ifidx>", true},
        {"veth_iface",     required_argument, NULL, 'Y'}, //"Iface id veth device <dev>[eth0]", "<ifidx>", true},
        {"eth0_iface",     required_argument, NULL, 'Z'}, //"Iface id eth0 device <dev>[eth0]", "<ifidx>", true},
        {"redirect",       required_argument, NULL, 'r'}, // to redirect egress packet to eth0 iface or not
        {"source_ip",      required_argument, NULL, 's'}, //"Source IP address of <dev>", "<ip>", true},
        {"source_mac",     required_argument, NULL, 'S'}, //"Source MAC addr of <dev>", "<mac>", true},
        {"dest_ip",        required_argument, NULL, 'd'}, //"Destination IP addr of <redirect-dev>", "<ip>", true},
        {"dest_mac",       required_argument, NULL, 'D'}, //"Destination MAC addr of <redirect-dev>", "<mac>", true},
        {"inner_dest_mac", required_argument, NULL, 'M'}, //"Inner Destination MAC address", "<mac>", true},
        {"enable_logs",    required_argument, NULL, 'l'},
        {"inner_src_ip",   required_argument, NULL, 'x'}, //source ip of the container.
        {"inner_dst_ip",   required_argument, NULL, 'y'}, //dest ip of the container.
        {0, 0, NULL, 0}
};

// TODO: refactor?
int verify_args(mptm_info *mptm) {
    int action = mptm->action;

    // Key is always needed.
    if (mptm->inner_src_addr[0] == '\0' || mptm->inner_dst_addr[0] == '\0') {
        eprintf("source_addr and dest_addr form the key and are not provided\n");
        return -1;
    }

    if (action == MAP_GET || action == MAP_DELETE) {
        goto verified;
    }

    if (mptm->veth_iface == -1 || mptm->vpeer_iface == -1) {
        eprintf("veth_iface and vpeer_iface are not provided\n");
        return -1;
    }

    if (mptm->redirect == 1) {
        if (mptm->eth0_iface == -1) {
            eprintf("redirect is set but eth0_iface is not provided\n");
            return -1;
        }
    }

    switch (mptm->tunnel)
    {
    case GENEVE:
        if (mptm->vlid == -1 || mptm->flags == -1 || mptm->source_port == -1 ||
            mptm->source_addr[0] == '\0' || mptm->dest_addr[0] == '\0' ||
            mptm->outer_dest_mac[0] == '\0' || mptm->source_mac[0] == '\0' || mptm->inner_dest_mac[0] == '\0') {
            // if we need to add then we need all the other info to create
            // tunnel structure.
            eprintf("operation is add but all argumnets are not provided\n");
            return -1;
        }
      break;
    case VLAN:
        if (mptm->vlid == -1) {
            eprintf("operation is add but all argumnets are not provided\n");
            return -1;
        }
      break;
    default:
        eprintf("Unknown type of tunnel\n");
        return -1;
    }

verified:
    printf("Arguments verified\n");
    return 0;
}

// Change name of verbose to logs (-l/--enable_logs)
int parse_params(int argc, char *argv[], mptm_info *mptm) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "h:a:t:v:f:p:I:R:s:S:d:D:M:l:",
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'h' :
            print_usage();
            exit(0);
        case 'a' :
            if(strcmp(optarg, "ADD") == 0) {
                mptm->action = MAP_ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                mptm->action = MAP_DELETE;
            } else if(strcmp(optarg, "GET") == 0) {
                mptm->action = MAP_GET;
            } else {
                eprintf("INVALID value for option -o %s\n", optarg);
                return -1;
            }
            break;
        case 't' :
            if(strcmp(optarg, "VLAN") == 0) {
                mptm->tunnel = VLAN;
            } else if(strcmp(optarg, "GENEVE") == 0) {
                mptm->tunnel = GENEVE;
            } else {
                eprintf("INVALID value for tunnel -t %s\n", optarg);
                return -1;
            }
            break;
        case 'v' : 
            if (!optarg) {
                mptm->vlid = -1;
                break;
            }
            mptm->vlid = atol(optarg);
            break;
        case 'f' : 
            if (!optarg) {
                mptm->flags = -1;
                break;
            }
            mptm->flags = atoi(optarg);
            break;
        case 'p' :
            if (!optarg) {
                mptm->source_port = -1;
                break;
            }
            mptm->source_port = atoi(optarg); 
            break;
        case 'X' : 
            if (!optarg) {
                mptm->vpeer_iface = 0;
                break;
            }
            mptm->vpeer_iface = atoi(optarg);
            break;
        case 'Y' : 
            if (!optarg) {
                mptm->veth_iface = 0;
                break;
            }
            mptm->veth_iface = atoi(optarg);
            break;
        case 'Z' : 
            if (!optarg) {
                mptm->eth0_iface = 0;
                break;
            }
            mptm->eth0_iface = atoi(optarg);
            break;
        case 'r' :
            if (!optarg) {
                mptm->redirect = 0;
                break;
            }
            mptm->redirect = atoi(optarg);
            break;
        case 's' : strncpy(mptm->source_addr, optarg, 16);
            break;
        case 'd' : strncpy(mptm->dest_addr, optarg, 16);
            break;
        case 'S' : strncpy(mptm->source_mac, optarg, 18);
            break;
        case 'D' : strncpy(mptm->outer_dest_mac, optarg, 18);
            break;
        case 'M' : strncpy(mptm->inner_dest_mac, optarg, 18);
            break;
        case 'x' : strncpy(mptm->inner_src_addr, optarg, 16);
            break;
        case 'y' : strncpy(mptm->inner_dst_addr, optarg, 16);
            break;
        case 'l' :
            if (!optarg) {
                mptm->debug = 0;
                break;
            }
            mptm->debug = atoi(optarg);
            break;
        default:
            eprintf("INVALID parameter supplied %c\n", opt);
            return -1;
      }
    }

    return verify_args(mptm);
}

tunnel_map_key_t *__get_tunnel_info_map_key(mptm_info *mptm, bool inverted) {
    tunnel_map_key_t *key = (tunnel_map_key_t *)malloc(sizeof(tunnel_map_key_t));;

    /*
     We need to convert them individually to network byte order format
     and then combine to form the key because in the xdp program
     key is constructed by using the saddr and daddr directly from
     the packet and hence saves us two bswaps on each packet.
    */
    uint32_t s_addr = ipv4_to_ineta(mptm->inner_src_addr);
    uint32_t d_addr = ipv4_to_ineta(mptm->inner_dst_addr);

    if (inverted) {
        key->s_addr = d_addr;
        key->d_addr = s_addr;
    } else {
        key->s_addr = s_addr;
        key->d_addr = d_addr;
    }

    return key;
}

mptm_tunnel_info* create_tun_info(mptm_info *mptm) {

    mptm_tunnel_info *tn = (mptm_tunnel_info *)malloc(sizeof(mptm_tunnel_info));

    tn->debug = mptm->debug;
    tn->tunnel_type = mptm->tunnel;
    tn->redirect = mptm->redirect;
    tn->flags = mptm->flags;

    tn->eth0_iface = mptm->eth0_iface;
    tn->veth_iface = mptm->veth_iface;

    switch (mptm->tunnel) {
    case VLAN: {
        struct vlan_info *vlan = (struct vlan_info *)(&tn->tnl_info.vlan);
        vlan->vlan_id = mptm->vlid;
      }
      break;
    case GENEVE: {
        struct geneve_info *geneve = (struct geneve_info *)(&tn->tnl_info.geneve);
        geneve->vlan_id = mptm->vlid;
        geneve->source_port = __bswap_16(mptm->source_port);
        if (parse_mac(mptm->source_mac, geneve->source_mac) < 0) {
            eprintf("source_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->outer_dest_mac, geneve->dest_mac) < 0) {
            eprintf("outer_dest_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->inner_dest_mac, geneve->inner_dest_mac) < 0) {
            eprintf("inner_d_mac value is incorrect\n");
            return NULL;
        }
        geneve->dest_addr = ipv4_to_ineta(mptm->dest_addr);
        if (geneve->dest_addr == 0) {
            eprintf("dest_addr value is incorrect\n");
            return NULL;
        }
        geneve->source_addr = ipv4_to_ineta(mptm->source_addr);
        if (geneve->source_addr == 0) {
            eprintf("source_addr value is incorrect\n");
            return NULL;
        }
      }
      break;
    default:
        break;
    }

     return tn;
}

void dump_tunnel_info(mptm_tunnel_info *tn) {
    if (tn == NULL) {
        return;
    }

    printf("Tunnel info element - {\n");
    printf("\tdebug = %u\n", tn->debug);
    printf("\tredirect = %u\n", tn->redirect);
    printf("\tflags = %u\n", tn->flags);
    printf("\teth0_iface = %d\n", tn->eth0_iface);
    printf("\tveth_iface = %d\n", tn->veth_iface);
    printf("\ttunnel_type = %s\n", get_tunnel_name(tn->tunnel_type));
    switch (tn->tunnel_type)
    {
    case VLAN: {
        struct vlan_info *vlan = (struct vlan_info *)(&tn->tnl_info.vlan);
        printf("\tvlan_id = %u\n", vlan->vlan_id);
    }
    break;
    case GENEVE: {
        struct geneve_info *geneve = (struct geneve_info *)(&tn->tnl_info.geneve);
        printf("\tvlan_id = %llu\n", geneve->vlan_id);
        printf("\tsource_port = %u\n", geneve->source_port);
        printf("\tsource_mac = %s\n", decode_mac(geneve->source_mac));
        printf("\touter_dest_mac = %s\n", decode_mac(geneve->dest_mac));
        printf("\tinner_dest_mac = %s\n", decode_mac(geneve->inner_dest_mac));
        printf("\tdest_ip = %s\n", decode_ipv4(geneve->dest_addr));
        printf("\tsource_ip = %s\n", decode_ipv4(geneve->source_addr));
    }
    break;
    default:
        printf("Unknown tunnel type %d\n", tn->tunnel_type);
        break;
    }
    printf("}\n");
}

int do_get(mptm_info *mptm) {
    int ret;
    uint32_t ingress_redirect_if, egress_redirect_if;
    mptm_tunnel_info *ti = (mptm_tunnel_info *)malloc(sizeof(mptm_tunnel_info));

    ret = lookup_map(mptm->tunnel_map_fd, mptm->tun_key, ti, TUNNEL_INFO_MAP);
    if (ret != EXIT_OK) {
        eprintf("failed to lookup tunnel info\n");
        return ret;
    }

    ret = lookup_map(mptm->redirect_if_devmap_fd, &ti->veth_iface, &egress_redirect_if, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to lookup redirect ingress interface\n");
        return ret;
    }

    ret = lookup_map(mptm->redirect_if_devmap_fd, &ti->eth0_iface, &ingress_redirect_if, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to lookup redirect egress interface\n");
        return ret;
    }

    dump_tunnel_info(ti);

    printf("Ingrese redirect is from iface %d to %d\n",
            ti->veth_iface, egress_redirect_if);
    printf("Egrese redirect is from iface %d to %d\n",
            ti->eth0_iface, ingress_redirect_if);

    return EXIT_OK;
}

int do_delete(mptm_info *mptm) {
    int ret;

    uint32_t ingress_if, egress_if;
    mptm_tunnel_info *ti = (mptm_tunnel_info *)malloc(sizeof(mptm_tunnel_info));

    ret = lookup_map(mptm->tunnel_map_fd, mptm->tun_key, ti, TUNNEL_INFO_MAP);
    if (ret != EXIT_OK) {
        eprintf("failed to lookup tunnel info\n");
        return ret;
    }

    ingress_if = ti->veth_iface;
    egress_if = ti->eth0_iface;

    ret = update_map(mptm->tunnel_map_fd, MAP_DELETE, mptm->tun_key, NULL, 0, TUNNEL_INFO_MAP);
    if (ret != EXIT_OK) {
        eprintf("failed to delete tunnel info\n");
        return ret;
    }
    ret = update_map(mptm->redirect_if_devmap_fd, MAP_DELETE, &ingress_if, NULL, 0, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to delete ingress_if redirect info\n");
        return ret;
    }
    ret = update_map(mptm->redirect_if_devmap_fd, MAP_DELETE, &egress_if, NULL, 0, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to delete egress_if redirect info\n");
        return ret;
    }
    return EXIT_OK;
}

int do_add(mptm_info *mptm) {
    int ret;

    mptm_tunnel_info *ti = NULL;
    printf("Creating tunnel info object......");
    ti = create_tun_info(mptm);
    if(ti == NULL) {
        eprintf("failed creating struct\n");
        return EXIT_FAIL_OPTION;
    }
    printf("created\n");

    ret = update_map(mptm->tunnel_map_fd, MAP_ADD, mptm->tun_key, ti, 0, TUNNEL_INFO_MAP);
    if (ret != EXIT_OK) {
        eprintf("failed to add tunnel info\n");
        return ret;
    }

    uint32_t ingress_if = mptm->veth_iface;
    uint32_t egress_if = mptm->eth0_iface;

    ret = update_map(mptm->redirect_if_devmap_fd, MAP_ADD, &ingress_if, &egress_if, 0, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to add redirect if\n");
        return ret;
    }

    ret = update_map(mptm->redirect_if_devmap_fd, MAP_ADD, &egress_if, &ingress_if, 0, REDIRECT_IF_DEVMAP);
    if (ret != EXIT_OK) {
        eprintf("failed to add inverse redirect if\n");
        return ret;
    }

    return EXIT_OK;
}

int main(int argc, char **argv) {

    int ret;
    mptm_info *mptm = (mptm_info *)malloc(sizeof(mptm_info));

    if (parse_params(argc, argv, mptm) != 0) {
        eprintf("parsing params failed\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* Open the map for geneve config */
    int tunnel_map_fd = load_bpf_mapfile(PIN_BASE_DIR, TUNNEL_INFO_MAP);
    if (tunnel_map_fd < 0) {
          eprintf("cannot open tunnel iface map\n");
        return EXIT_FAIL_BPF;
    }
    printf("Opened bpf map file %s/%s at fd %d\n", PIN_BASE_DIR, TUNNEL_INFO_MAP, tunnel_map_fd);

    /* Open the map for geneve config */
    int redirect_if_devmap_fd = load_bpf_mapfile(PIN_BASE_DIR, REDIRECT_IF_DEVMAP);
    if (redirect_if_devmap_fd < 0) {
          eprintf("cannot open redirect if devmap\n");
        return EXIT_FAIL_BPF;
    }
    printf("Opened bpf map file %s/%s at fd %d\n", PIN_BASE_DIR, REDIRECT_IF_DEVMAP, redirect_if_devmap_fd);

    mptm->tunnel_map_fd = tunnel_map_fd;
    mptm->redirect_if_devmap_fd = redirect_if_devmap_fd;

    mptm->tun_key = TUNNEL_INFO_KEY(mptm);
    if (mptm->tun_key == NULL) {
      eprintf("cannot create tunnel key\n");
    }

    switch (mptm->action)
    {
    case MAP_GET:
        ret = do_get(mptm);
        break;
    case MAP_ADD:
        ret = do_add(mptm);
        break;
    case MAP_DELETE:
        ret = do_delete(mptm);
        break;
    }

    return ret;
}
