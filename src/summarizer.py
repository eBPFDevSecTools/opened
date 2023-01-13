#Authors:
# Palani Kodeswaran (palani@in.ibm.com)
# Sayandeep Sen (sayandes@in.ibm.com)

import os
import subprocess
import argparse
import json
import re
from helper_summarizer import build_helper_desc_dict
import remove_c_style_comments as rmc
from collections import defaultdict

CAP="capability"

def create_capability_json(cap_dict, manpage_info_dict):
    json_data_list = []
    for cap_name in cap_dict.keys():
        data = {}
        #data["capability"] = cap_name
        lst = []
        for helper in list(cap_dict[cap_name]):
            #print("got "+helper+"->"+str(manpage_info_dict[helper]["Function Name"]))
            lst.append(manpage_info_dict[helper])
        data[cap_name]=lst
        json_data_list.append(data)
    return json_data_list


def add_dict_to_cap_dict(cap_dict,cap_name):
    if  not (cap_name in cap_dict):
        cap_dict[cap_name] = {}
        
def add_helper_to_dict(cap_dict,cap_name,helper_name):
    try:
        helper_dict = cap_dict[cap_name]
        helper_dict[helper_name] = 1
    except Exception as e:
        print(e)

def generate_capabilities(helper_list,cap_dict):
    capabilities = {}
    #print("Capabilities")
    for cap_name in cap_dict.keys():
        helpers=set()
        #print(cap_name)
        cap_helpers = cap_dict[cap_name]
        #print("cap_helpers")
        #print(cap_helpers)
        for helper_name in helper_list:
            #print(helper_name)
            if helper_name in cap_helpers.keys():
                #print("Adding: "+cap_name)
                helpers.add(helper_name)
        if len(helpers) > 0:
            #capabilities[cap_name]=set_to_string(helpers)
            capabilities[cap_name]=helpers
    return capabilities
        
'''
#capability,map_read
bpf_map_peek_elem,1
bpf_map_lookup_elem,1

'''
def load_capability_file(file_name, cap_dict):
    cap_name = ""
    try:
        f = open(file_name,'r')
        for line in f.readlines():
            line = line.strip()
            if "#" in line:
                if CAP in line:
                    tokens = line.split(",")
                    cap_name = tokens[1]
                    add_dict_to_cap_dict(cap_dict,cap_name)
            else:
                tokens = line.split(",")
                helper_name = tokens[0]
                value = tokens[1]

                if int(value) == 1:
                    #print(helper_name)
                    add_helper_to_dict(cap_dict,cap_name,helper_name)
    except Exception as e:
        print(e)
    
    

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


def load_bpf_helper_map(fname):
    data = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    return data


def load_manpage_helper_map(fname):
    data = []
    ret = {}
    try:
        with open(fname, 'r') as f:
            data = json.load(f)
    except IOError as e:
        print("Could not open file: "+fname)
    for entry in data:
        keys = entry.keys()
        for keys in entry:
            ret[keys] = entry[keys]
    return ret



def check_and_return_func_present(my_dict,line):
    for key in my_dict.keys():
        if line.find(key)>=0:
            return key
    return None

def append_helper_details(line, helper, helper_set, helperCallParams):
    helper_set.add(helper)
    details_dict = {}
    # save the op variable name and arguments
    #print("line:"+line+" END")
    re.sub(' +', ' ',line)
    if'=' in line:
        details_dict["opVar"] = line.split('=')[0]
        rest = line.split('=')[1].replace("(","").replace(")","")
    else:
        details_dict["opVar"] = "NA"
        rest = line
    rest = rest.replace(helper,"").replace("(","").replace(")","")
    details_dict["inpVar"] = rest.split(",")
    helperCallParams[helper].append(json.dumps(details_dict,indent=1))
def append_return_details(ret_type, rettypedict, ret_set):
    #print("RETURN TYPE: "+ret_type+" value: "+str(rettypedict[ret_type]))
    ret_set.add(ret_type)
    return
def get_helper_encoding(lines, helperdict, helperCallParams, rettypedict):
    helper_set= set()
    ret_set= set()
    for line in lines:
        helper=check_and_return_func_present(helperdict,line)
        if helper != None:
            append_helper_details(line, helper, helper_set, helperCallParams)
        ret_type = check_and_return_func_present(rettypedict, line)
        if ret_type != None:
            append_return_details(ret_type, rettypedict, ret_set)
    str =  ""
    for helper in helper_set:
        str = str + helper +","
    for ret in ret_set:
        str = str + ret +","
    #print(str)
    return str


def set_to_string(my_set):
    str =  ""
    for elem in my_set:
        str = str + elem +","
    return str


def get_read_maps(lines):
    map_read_set=set()
    for line in lines:
        mapname= check_map_access(map_read_fn,line)
        if mapname != None:
            map_read_set.add(mapname)
    return set_to_string(map_read_set)
            
def get_update_maps(lines):
    map_update_set=set()
    for line in lines:
        mapname= check_map_access(map_update_fn,line)
        if mapname != None:
            map_update_set.add(mapname)
    return set_to_string(map_update_set)


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
    #TODO: we need to ignore commented code.
    lines = "".join(ifile.readlines()[beg:end])
    lines = rmc.removeComments(lines)
    lines = lines.replace("}","").replace("{",";").replace("\n","");
    return lines.split(";")

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
    bpf_helper_file= '../asset/helper_hookpoint_map.json'
    map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
    map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
    isCilium=args.isCilium

    if(isCilium == True):
        print("Warning: bpf_helper_file not specified using default asset/helper_hookpoint_map.json\n")
        bpf_helper_file = "asset/cilium.helper_hookpoint_map.json"
        map_update_fn = ["sock_map_update", "map_delete_elem", "map_update_elem","map_pop_elem", "map_push_elem"]
        map_read_fn = ["map_peek_elem", "map_lookup_elem", "map_pop_elem"]
    
    if(args.bpfHelperFile is not None):
        bpf_helper_file = args.bpfHelperFile
    
    helperdict = load_bpf_helper_map(bpf_helper_file)

    helper_to_desc_dict = {}
    '''
    cmd = "bpftool prog loadall " + fname+ " /sys/fs/bpf/check type tc"
    run_cmd(cmd)
    cmd =  "bpftool prog show"
    output = run_cmd(cmd)
    prog_id = get_prog_id(sec_name,output)
    cmd = "bpftool prog dump xlated id " + prog_id +  " > out"
    output = run_cmd(cmd)
    print(output)
    cmd = "grep \";\" out > decompiled.c"
    output = run_cmd(cmd)
    print(output)
'''
    ifile = open('decompiled.c','r')
    lines = ifile.readlines();
    helperCallParams = {}
    encoding = get_helper_encoding(lines,helperdict, helperCallParams)
    read_maps = get_read_maps(lines)
    update_maps = get_update_maps(lines)
    #print("Encoding: ",encoding,"Read Maps: ",read_maps,"Update Maps: ",update_maps)

    
    #print(rc.decode("utf-8"))
    #runbpftool()
def get_capability_dict(begL, endL, example_file, isCilium, bpfHelperFile):
    #Default init values
    read_pkt_file= "asset/bpf_helper_info/bpf_helpers_read_skb.txt"
    update_pkt_file= "asset/bpf_helper_info/bpf_helpers_mangle_skb.txt"
    read_map_file= "asset/bpf_helper_info/bpf_helpers_map_read.txt"
    update_map_file= "asset/bpf_helper_info/bpf_helpers_map_update.txt"
    read_sys_info_file= "asset/bpf_helper_info/bpf_helpers_read_sys_info.txt"
    capability_files = ["asset/bpf_helper_info/bpf_helpers_read_skb.txt", "asset/bpf_helper_info/bpf_helpers_mangle_skb.txt","asset/bpf_helper_info/bpf_helpers_map_read.txt","asset/bpf_helper_info/bpf_helpers_map_update.txt","asset/bpf_helper_info/bpf_helpers_read_sys_info.txt","asset/bpf_return_type_info/return_type_drop_pkt.txt","asset/bpf_return_type_info/return_type_pass_pkt.txt", "asset/bpf_return_type_info/return_type_redirect_pkt.txt"]
    bpf_helper_file= './asset/helper_hookpoint_map.json'
    map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
    map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
    manpage_info_file = "./asset/bpf_helpers_desc_mod.json"
    
    if(isCilium is True):
        print("Warning: bpf_helper_file not specified using default asset/helper_hookpoint_map.json\n")
        bpf_helper_file = "./asset/cilium.helper_hookpoint_map.json"
        map_update_fn = ["sock_map_update", "map_delete_elem", "map_update_elem","map_pop_elem", "map_push_elem"]
        map_read_fn = ["map_peek_elem", "map_lookup_elem", "map_pop_elem"]
        manpage_info_file = "./asset/cilium.bpf_helpers_desc_mod.json"
    
    cap_dict = {}
    for file_name in capability_files:
        load_capability_file(file_name,cap_dict)
    
    if(bpfHelperFile is not None):
        bpf_helper_file = bpfHelperFile
    helperdict = load_bpf_helper_map(bpf_helper_file)
    rettypedict = load_bpf_helper_map("./asset/PktRetTypesInfo.json")

    code_lines = read_src_file(example_file,begL,endL)
    helperCallParams = defaultdict(list)
    helpers = get_helper_encoding(code_lines, helperdict, helperCallParams, rettypedict).split(',')
    caps = generate_capabilities(helpers, cap_dict)

    #print(caps)
    manpage_info_dict = load_manpage_helper_map(manpage_info_file)
    op_dict = {}
    op_dict["capability"] = create_capability_json(caps, manpage_info_dict)
    op_dict["helperCallParams"] = helperCallParams
    return op_dict
