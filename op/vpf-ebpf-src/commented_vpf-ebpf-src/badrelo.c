// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

#define BPF_MAP_TYPE_ARRAY 2

__attribute__((section("maps"), used))
struct bpf_map map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(int),
     .value_size = 0,
     .max_entries = 1};

// This will be an unresolved symbol in the resulting .o file.
int bpf_map_update_elem(struct bpf_map* map, const void* key,
                        const void* value, uint64_t flags);

struct ctx;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "map_update": [
        {
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of:BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": "0 on success, or a negative error in case of failure.",
          "Return Type": "int",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_update_elem": [
      "{\n \"opVar\": \"NA\",\n \"inpVar\": [\n  \"            return &map2\",\n  \" const void*0\",\n  \" const void*0\",\n  \" 0\"\n ]\n}"
    ]
  },
  "startLine": 31,
  "endLine": 38,
  "File": "/home/sayandes/opened_extraction/examples/vpf-ebpf-src/badrelo.c",
  "Funcname": "func",
  "Update_maps": [
    " map2",
    ""
  ],
  "Read_maps": [
    ""
  ],
  "Input": [
    "struct ctx *ctx"
  ],
  "Output": "int",
  "Helper": "bpf_map_update_elem,",
  "human_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": ""
    }
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "author_email": "",
      "date": "",
      "params": ""
    }
  ]
}
,
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
int func(struct ctx* ctx)
{
    struct bpf_map map2;

    // And we can furthermore pass some bad parameters in here.  These
    // would be illegal to pass to bpf_map_update_elem if it were resolved.
    return bpf_map_update_elem(&map2, (const void*)0, (const void*)0, 0);
}
