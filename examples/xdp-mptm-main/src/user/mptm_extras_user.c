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

#include <user/lib/bpf-user-helpers.h>

#define REDIRECT_DEVMAP       "redirect_devmap"

int ingress_iface = -1;
int action;
int redirect_iface = -1;

/************************** Parsing functions ****************************/
void  print_usage() {
  printf("[USAGE]: i(ingress_iface):r(redirect_iface):a(action)\n");
  printf("i:ingress interface r:redirect iface to redirect a:[ADD/DEL]\n");
}

static const struct option long_options[] = {
        {"action",         required_argument, 0, 'a'},
        {"ingress_iface",  required_argument, 0, 'i'},
        {"redirect_iface", required_argument, 0, 'r'},
        {0, 0, NULL, 0}
};

int parse_params(int argc, char *argv[]) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "i:a:r:",
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'i' : ingress_iface = atoi(optarg);
            break;
        case 'r' : redirect_iface = atoi(optarg);
            break;    
        case 'a' :
            if(strcmp(optarg, "ADD") == 0) {
                action = MAP_ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                action = MAP_DELETE;
            } else {
                eprintf("INVALID value for action -a %s\n", optarg);
                return -1;
            }
            break;
        default:
            eprintf("INVALID parameter supplied %c \n", opt);
            return -1;
      }
    }

    if (action == MAP_ADD && (ingress_iface == -1 || redirect_iface == -1)) {
        eprintf("Need all parameters for ADD\n");
        // for ADD we need capture iface and iface with redirect iface id.
        return -1;
    } else if(action == MAP_DELETE && ingress_iface == -1 ) {
        eprintf("Need ingress iface for DELETE\n");
        // for delete we only need the iface which is they key in map
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {

    if (parse_params(argc, argv) != 0) {
        eprintf("error parsing params\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* Make map for redirection port entries */
    int redirect_map_fd = load_bpf_mapfile(PIN_BASE_DIR, REDIRECT_DEVMAP);
    if (redirect_map_fd < 0) {
        eprintf("error opening redirect map\n");
        return EXIT_FAIL_BPF;
    }
    printf("ingress iface:%d, redirect iface:%d, action:%s\n",
            ingress_iface, redirect_iface, action ? "DELETE" : "ADD" );

    return update_map(redirect_map_fd, action, &ingress_iface,
                      &redirect_iface, 0, REDIRECT_DEVMAP);
}

