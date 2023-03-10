#Authors:
# Palani Kodeswaran (palani@in.ibm.com)
# Sayandeep Sen (sayandes@in.ibm.com)

import os
import subprocess
import argparse
import json
import re
import remove_c_style_comments as rmc
from collections import defaultdict

CAP="capability"

def get_read_maps(lines, map_read_fn):
    map_read_set=set()
    for line in lines:
        mapname= check_map_access(map_read_fn,line)
        if mapname != None:
            map_read_set.add(mapname)
    return list(map_read_set)

def get_update_maps(lines, map_update_fn):
    map_update_set=set()
    for line in lines:
        mapname= check_map_access(map_update_fn,line)
        if mapname != None:
            map_update_set.add(mapname)
    return list(map_update_set)

def get_helper_list(lines,helperdict):
    helper_set= set()
    for line in lines:
        present= check_and_return_func_present(helperdict,line)
        if present != None:
            helper_set.update(present)
    return list(helper_set)

def create_capability_dict(helper_list, helperdict):
    cap_dict = {}
    for fn in helper_list:
        for cap in helperdict[fn]['capabilities']:
            if cap not in cap_dict:
                cap_dict[cap] = list()
            cap_dict[cap].append(fn)

    data_list = []
    for cap_name in cap_dict.keys():
        data = {}
        data["capability"] = cap_name
        lst = []
        for helper in cap_dict[cap_name]:
            #print("got "+helper+"->")#+str(manpage_info_dict[helper]["Function Name"]))
            lst.append(helperdict[helper])
        data[cap_name]=lst
        data_list.append(data)
    return data_list

def get_compatible_hookpoints(helpers,helper_hookpoint_dict):
    hook_set = None
    if helpers is None or len(helpers) == 0:
        hook_set = get_all_available_hookpoints(helper_hookpoint_dict)
        print("Helpers None: ")
        print(hook_set)
        return list(hook_set)
        #return ["All_hookpoints"]
    
    for helper in set(helpers):
        if 'compatible_hookpoints' not in helper_hookpoint_dict[helper]:
            continue

        helper_set = set(helper_hookpoint_dict[helper]["compatible_hookpoints"])
        if hook_set == None:
            hook_set = helper_set
        else:
            hook_set = hook_set.intersection(helper_set)
    if hook_set is None:
        return None
    return list(hook_set)


def decompile(prog_file):
    lines = []
    cmd = "bpftool prog dump xlated pinned " + prog_file + " > temp.c"
    output = run_cmd(cmd)

    #remove ; from bpftool output
    cmd = "grep \";\" temp.c > dumped.c"
    # check bpftool version. some verions dont have ";"
    #output = run_cmd(cmd)
    #open dumped.c
    dumped_file = open("dumped.c",'r')

    for line in dumped_file.readlines():
        print(line)
    return lines

def load_bpf_helper_cap(fname):
    data = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    return data


def load_bpf_helper_map(fname):
    print("Filename: "+fname)
    data = []
    ret = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    for entry in data:
        #print("This is entry: "+entry)
        keys = entry.keys()
        for keys in entry:
            ret[keys] = entry[keys]
    return ret

def check_and_return_func_present(my_dict,line):
    hls =  list()
    for key in my_dict.keys():
        if line.find(key)>=0:
            hls.append(key)
    return hls

def get_helper_encoding(lines, helperdict, helperCallParams):
    helper_set= set()
    for line in lines:
        helper_list = check_and_return_func_present(helperdict,line)
        if len(helper_list) > 0:
            #experimental stuff disabled for now XXX
            #for helper in helper_list:
            #append_helper_details(line, helper, helper_set, helperCallParams)
            helper_set.update(helper_list)
    return list(helper_set)

def get_prog_id(sec_name,output):
    lines = output.split("\n")
    #print(lines)
    last_line=""
    for line in lines:
        if sec_name in line:
            print(line)
            last_line = line
    #print("Get prog_id: ",last_line)
    prog_id = last_line.split(":")[0]
    print(prog_id)
    return prog_id

def check_map_access(my_arr,line):
    for func in my_arr:
        idx = line.find(func)
        if idx>=0:
            chunks = line[len(func)+idx:].replace('(','')
            first_entry_end = chunks.find(',')
            return chunks[:first_entry_end].replace("&","")
    return None


def run_cmd(cmd):
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True) as process:
        output = process.communicate()[0].decode("utf-8")
        print(output)
        return output

def read_src_file(fname,beg,end):
    ifile = open(fname,'r')
    lines = "".join(ifile.readlines()[beg:end])
    lines = rmc.removeComments(lines)
    lines = lines.replace("}","").replace("{",";").replace("\n","");
    return lines.split(";")
    
def get_capability_dict(begL, endL, example_file, isCilium, helperdict):
    code_lines = read_src_file(example_file,begL,endL)

    helperCallParams = defaultdict(list)
    helpers_list = get_helper_encoding(code_lines, helperdict, helperCallParams)
    op_dict = {}
    op_dict["capabilities"] = create_capability_dict(helpers_list, helperdict)
    op_dict["helperCallParams"] = helperCallParams
    return op_dict


def get_all_available_hookpoints(helper_hookpoint_dict):
    hookpoint_set = set()
    for info_str in helper_hookpoint_dict.values():
        if info_str is None or "compatible_hookpoints" not in info_str:
            continue
        hookpoint_set.update(info_str["compatible_hookpoints"])
    return list(hookpoint_set)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='eBPF Code Summarizer')

    parser.add_argument('-f','--bpfHelperFile', type=str,required=False,
            help='Information regarding bpf_helper_funcitons ')

    parser.add_argument('-s','--srcFile', type=str,required=True,
            help='eBPF ELF file')

    parser.add_argument('-e','--secName', type=str,required=True,
            help='Section Name')
    parser.add_argument('-q','--isCilium', type=bool,required=True,
            help='whether repository is cilium')


    args = parser.parse_args()

    print("Args",args)


    
    fname = args.srcFile
    sec_name = args.secName
    bpf_helper_file= '../asset/bpf_helpers_desc_mod.json'
    map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
    map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
    isCilium=args.isCilium

    if(isCilium == True):
        print("Warning: bpf_helper_file not specified using default asset/cilium.helper_hookpoint_map.json\n")
        map_update_fn = ["sock_map_update", "map_delete_elem", "map_update_elem","map_pop_elem", "map_push_elem"]
        map_read_fn = ["map_peek_elem", "map_lookup_elem", "map_pop_elem"]
    
    if(args.bpfHelperFile is not None):
        bpf_helper_file = args.bpfHelperFile
    
    helperdict = load_bpf_helper_map(bpf_helper_file)

    helper_to_desc_dict = {}

    ifile = open('decompiled.c','r')
    lines = ifile.readlines();
    helperCallParams = {}
    encoding = get_helper_encoding(lines, helperdict, helperCallParams)
