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

#rm cscope.files cscope.out tags myproject.db 
def clean_intermediate_files(file_list):
    for file_path in file_list:
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

def create_directories(dir_list):
    for dr in dir_list:
        if not os.path.exists(dr):
            os.makedirs(dr, exist_ok=True)


def create_cqmakedb(db_file, cscope_file, tags_folder):
    run_cmd("cqmakedb -s "+db_file+" -c "+cscope_file+" -t "+tags_folder+" -p")
    return

#cqmakedb -s ./myproject.db -c ./cscope.out -t ./tags -p
def make_cscope_db(db_name,code_dir, cscope_files,cscope_out,tage_folder):
    op_file = open(cscope_files,'w')
    files = glob.glob(code_dir + '/**/*.c', recursive=True)
    for f in files:
        op_file.write(f)
        op_file.write("\n")

    files = glob.glob(code_dir + '/**/*.h', recursive=True)
    for f in files:
        op_file.write(f)
        op_file.write("\n")
    op_file.close()        
    run_cmd("cscope -cb -k -i "+cscope_files)
    run_cmd("ctags --fields=+i -n -L "+cscope_files)
    run_cmd("cqmakedb -s "+ db_name+ " -c "+cscope_out+" -t "+tags_folder+" -p")


def check_if_cmd_available():
    commands = ['cscope', 'ctags', 'cqmakedb', 'cqsearch']
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
    parser.add_argument('-s','--src_dir',action='store',required=True,help='directory with source code')
    parser.add_argument('-f','--function_name',action='store',required=True, help='function name to be extracted')
    parser.add_argument('-d','--db_file_name',action='store',required=False, help='Optional sqlite3 database with cqmakedb info')
    parser.add_argument('-g','--function_call_graph_path',action='store',required=False, help='directory to put function and map dependency call graph file. Output of phase I')
    parser.add_argument('-r','--repo_name',action='store',required=True, help='Project repository name')

    args = parser.parse_args()
    
    if(not check_if_cmd_available()):
        exit(1)

    dir_list = []
    function_name= args.function_name
    opf_file_path = "./"
    if (args.function_call_graph_path is not None):
        opf_file_path = args.function_call_graph_path+"/"
    if (os.access(opf_file_path, os.W_OK) is not True):
        print("Cannot write fcg to: " + opf_file_path + " Creating...")
        create_directories([opf_file_path])
    
    cscope_files = "cscope.files"
    cscope_out = "cscope.out"
    tags_folder = "tags"
    intermediate_f_list = []
    intermediate_f_list.append(cscope_out)
    intermediate_f_list.append(tags_folder)


    repo_name = args.repo_name
    
    db_file = args.db_file_name
    if db_file is None or db_file == '':
        db_file = repo_name+".db"
        make_cscope_db(db_file,args.src_dir,cscope_files,cscope_out,tags_folder)
        # run code query to generate annotated function call graph
        create_cqmakedb(db_file, cscope_out, tags_folder)

    opf_name = opf_file_path + repo_name+ "." + function_name + ".cg.out"
    search_function(function_name, db_file, opf_name)
    clean_intermediate_files(intermediate_f_list)
