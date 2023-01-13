// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

typedef struct bpf_map_def {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;
#define BPF_MAP_TYPE_ARRAY 2

__attribute__((section("maps"), used))
bpf_map_def_t map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(int),
     .value_size = sizeof(uint32_t),
     .max_entries = 1};

static void* (*bpf_map_lookup_elem)(bpf_map_def_t* map, void* key) = (void*) 1;

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/vpf-ebpf-src/mapvalue-overrun.c,
 Startline: 26,
 Endline: 39,
 Funcname: func,
 Input: (void *ctx),
 Output: int,
 Helpers: [bpf_map_lookup_elem,],
 Read_maps: [ map,],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
int func(void* ctx)
{
    uint32_t key = 1;

    uint64_t* ptr = bpf_map_lookup_elem(&map, &key);
    if (ptr == 0) {
        return 0;
    }

    // The map's value size can only hold a uint32_t.
    // So verification should fail if we try to read past the space returned.
    uint64_t i = *ptr;
    return (uint32_t)i;
}
