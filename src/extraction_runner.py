# Author Info:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

import os
import re
import subprocess
import glob
import shutil
import argparse
import json
from collections import defaultdict

def check_if_cmd_available():
    commands = ['cqsearch']
    for cmd in commands:
        if shutil.which(cmd) is None:
            print("Command: ",cmd," unavailable.. ", "Exiting")
            return False
    return True

def run_cmd(cmd):
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Running: ",cmd)
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output

def search_function(function_name, db_file, opf_name):
    print("Running cqsearch for ",function_name," and outputting dependencies to "+ opf_name)
    status=run_cmd("cqsearch -s "+db_file+" -t "+function_name+"  -p 7  -l 100 -k 10 -e -o "+ opf_name)
    base_dir = os.getcwd()
    cmd_str=" sed -i  -e \"s|\$HOME|"+base_dir+"|g\" " +opf_name
    status=run_cmd(cmd_str)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f','--function_name',action='store',required=True, help='function name to be extracted')
    parser.add_argument('-d','--db_file_name',action='store',required=True, help='sqlite3 database with cqmakedb info')
    parser.add_argument('-g','--function_call_graph_path',action='store',required=False, help='directory to put function and map dependency call graph file. Output of phase I')
    parser.add_argument('-r','--repo_name',action='store',required=False, help='Project repository name')

    args = parser.parse_args()
    
    if(not check_if_cmd_available()):
        exit(1)

    dir_list = []
    function_name= args.function_name
    opf_file_path = "./"
    if (args.function_call_graph_path is not None):
        opf_file_path = args.function_call_graph_path+"/"
    if (os.access(opf_file_path, os.W_OK) is not True):
        print("Cannot write fcg to: " + opf_file_path + " Exiting...")
        exit(1)
    db_file = args.db_file_name 
    repo_name = ""
    if(args.repo_name is not None):
        repo_name = args.repo_name
    opf_name = opf_file_path + repo_name+ "." + function_name + ".cg.out"
    search_function(function_name, db_file, opf_name)
