# Author Info:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

import os
import re
import subprocess
import glob
#import command
import shutil
import code_commentor as cmt
import argparse
import json
from collections import defaultdict

def check_if_cmd_available():
    commands = ['cqsearch']
    for cmd in commands:
        if shutil.which(cmd) is None:
            print("Command: ",cmd," unavailable.. ", "Exiting")
            return False
    print("All necessary commands found...")
    return True

def run_cmd(cmd):
    print("Running: ",cmd)
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output
    
def get_src_file(line):
    line = line.replace('[','')
    line = line.replace(']','')
    tokens = line.split(',')
    fnName = tokens[0]
    count = tokens[1]
    if int(count) > 1:
        return
    src = tokens[2]
    #Add headers included by .c files only
    if src.endswith(".c"):
        extracted_files.append(src)
    startLine = tokens[3]
    #remove end ]
    startLine = startLine[:-1]


# Parses output from codequery search output and puts in map
def parseFunctionList(ifile):
    ct = 0
    for line in ifile.readlines():
        m = re.match(r"[{}]",line)
        if m:
            #print("Ignoring",line)
            ct = ct + 1
        else:
            #print("ct",ct)
            if ct < 2:
                get_src_file(line)
            else:
                processMapLine(line)
            
def processMapLine(line):
    line = line.replace('[','')
    line = line.replace(']','')
    tokens = line.split(',')
    mapName = tokens[0]
    srcFile = tokens[1]
    startLine = tokens[2]
    isFound = tokens[3]
    ##print(fnName,count,src,startLine)
    #key=fnName+":"+src+":"+startLine
    key=mapName
    maps[key]=1


def create_code_comments(txl_dict, bpf_helper_file, opdir):
    map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
    map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
    helperdict = cmt.load_bpf_helper_map(bpf_helper_file)  
    for srcFile,txlFile in txl_dict.items():
        opFile = opdir+'/'+os.path.basename(srcFile)
        xmlFile = open(txlFile,'r')
        cmt.parseTXLFunctionOutputFileForComments(xmlFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn)
        xmlFile.close()
    return


def is_dup_map_in_extracted_files(dup_map_dict,extracted_files):
    op_map = defaultdict(list)
    for dup_map in dup_map_dict:
        def_files = dup_map_dict[dup_map]
        print(def_files)
        for dfile in def_files:
            if ".c" in dfile and dfile in extracted_files:
                print("Dup Struct" + dup_map+ " Defined in: "+dfile)
                op_map[dup_map].append(dfile)
    return op_map
                

def search_function(function_name, db_file, opf_name):
    print("Running cqsearch for ",function_name," and outputting dependencies to "+ opf_name)
    status=run_cmd("cqsearch -s "+db_file+" -t "+function_name+"  -p 7  -l 100 -k 10 -e -o "+ opf_name)
    base_dir = os.getcwd()
    cmd_str=" sed -i  -e \"s|\$HOME|"+base_dir+"|g\" " +opf_name
    status=run_cmd(cmd_str)

if __name__ == "__main__":

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-annotate_only',
            action='store',
            default=False)
    my_parser.add_argument('-f','--function_name',action='store',required=True,
            help='function name to be extracted')
    my_parser.add_argument('-d','--db_file_name',action='store',required=True,
            help='sqlite3 database with cqmakedb info')
    my_parser.add_argument('-g','--function_call_graph_path',action='store',required=False,
            help='directory to put function and map dependency call graph file. Output of phase I')
    my_parser.add_argument('-r','--repo_name',action='store',required=False,
            help='Project repository name')

    args = my_parser.parse_args()
    print(vars(args))
    if(not check_if_cmd_available()):
        exit(1)

    dir_list = []
    function_name= args.function_name
   
    opf_file_path = "./"
    if (args.function_call_graph_path is not None):
        opf_file_path = args.function_call_graph_path+"/"
    if (os.access(opf_file_path, os.W_OK) is not True):
        print("Cannot write fcg to: "+opf_file_path+" Exiting...")
        exit(1)

    db_file = args.db_file_name 
   
    opMaps=defaultdict(set)
    maps = {}
    dup_map_dict = defaultdict(list)
    extracted_files = []
    repo_name = ""
    if(args.repo_name is not None):
        repo_name = args.repo_name
    opf_name = opf_file_path+repo_name+"."+function_name+".cg.out"


    search_function(function_name, db_file, opf_name)

    # Read set of maps to be extracted to check for duplicate map definitions 
    ifile = open(opf_name,'r')
    parseFunctionList(ifile)
    ifile.close()
    print("Function graphs and map dependencies in: "+opf_name)
