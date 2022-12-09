# Author Info:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

import os
import re
import subprocess
import glob
import command
import shutil
import code_commentor as cmt
import argparse
import json
from collections import defaultdict

def check_if_cmd_available():
    commands = ['sed', 'txl', 'cscope', 'ctags', 'cqmakedb']
    for cmd in commands:
        if shutil.which(cmd) is None:
            print("Command: ",cmd," unavailable.. ", "Exiting")
            return False
    print("All necessary commands found...")
    return True

def check_if_file_available():
    files = [r'asset/c-extract-functions.txl', r'asset/c-extract-struct.txl', r'asset/c.grm.1', r'asset/bom.grm', r'asset/helper_hookpoint_map.json']
    for fl in files:
        if os.path.isfile(fl) is False:
            print("File: ",fl," unavailable.. ", "Exiting")
            return False
    print("All necessary asset files found...")
    return True
#1. make cscope db
#2. do txl annotation
#3. comment generation
#4. cqsearch

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

def run_cmd(cmd):
    print("Running: ",cmd)
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output

def create_directories(dir_list):
    for dr in dir_list:
        if not os.path.exists(dr):
            os.mkdir(dr)

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

def create_txl_annotation(cscope_file, opdir):
    print("Read cscope files and generate function annotation ...")
    txl_dict_func = {}
    txl_dict_struct = {}
    code_f = open(cscope_file,'r')
    for line in code_f.readlines():
        line = line.strip()
        full_line = run_cmd("readlink -f "+line)
        line = re.sub('^\.','',line) 
        line = re.sub('\/','_',line) 
        line = re.sub('^__','',line) 

        opfile_function_annotate= opdir+"/annotate_func_"+line+".xml"
        opfile_function_annotate= run_cmd("readlink -f "+opfile_function_annotate)
        opfile_struct_annotate= opdir+"/annotate_struct_"+line+".out"
        opfile_struct_annotate= run_cmd("readlink -f "+opfile_struct_annotate)
        logfile= opdir+"/LOG"

        print("File to annotate - ",full_line,"output in",opfile_function_annotate,opfile_struct_annotate)
        op = run_cmd("txl -o "+ opfile_function_annotate+" "+full_line+"  asset/c-extract-functions.txl")
        op = run_cmd("txl -o "+opfile_struct_annotate+" "+full_line +" asset/c-extract-struct.txl")
        txl_dict_func[full_line] = opfile_function_annotate
        txl_dict_struct[full_line] = opfile_struct_annotate
    return txl_dict_func,txl_dict_struct

def create_cqmakedb(db_file, cscope_file, tags_folder):
    run_cmd("cqmakedb -s "+db_file+" -c "+cscope_file+" -t "+tags_folder+" -p")
    return
   
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
                

if __name__ == "__main__":

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-annotate_only',
            action='store',
            default=False)
    my_parser.add_argument('-s','--src_dir',action='store',required=True,
            help='directory with source code')
    my_parser.add_argument('-o','--txl_op_dir',action='store',required=True,
            help='directory to put txl annotated files')
    my_parser.add_argument('-c','--opened_comment_stub_folder',action='store',required=False,
            help='directory to put source files with comment stub')
    my_parser.add_argument('-r','--bpfHelperFile', type=str,required=False,
            help='Information regarding bpf_helper_funcitons ')

    args = my_parser.parse_args()
    print(vars(args))
    if(not check_if_cmd_available() or not check_if_file_available()):
        exit(1)

    dir_list = []
    function_name= args.function_name
    
    src_dir = args.src_dir
    if (os.access(src_dir, os.R_OK) is not True):
        print("Cannot read source folder: "+src_dir+" Exiting...")
        exit(1)

    txl_op_dir = args.txl_op_dir
    dir_list.append(txl_op_dir)
    
    opf_file_path = "./"
    if (args.function_call_graph_path is not None):
        opf_file_path = args.function_call_graph_path+"/"
    if (os.access(opf_file_path, os.W_OK) is not True):
        print("Cannot write fcg to: "+opf_file_path+" Exiting...")
        exit(1)

    cmt_op_dir = None
    if (args.opened_comment_stub_folder is not None):
        cmt_op_dir = args.opened_comment_stub_folder
        dir_list.append(cmt_op_dir)

    create_directories(dir_list)
   
    if (os.access(txl_op_dir, os.W_OK) is not True):
        print("Cannot write to TXL files: "+txl_op_dir+" Exiting...")
        exit(1)
    if (cmt_op_dir is not None and os.access(cmt_op_dir, os.W_OK) is not True):
        print("Cannot write to commented_file dir: "+cmt_op_dir+" Exiting...")
        exit(1)



    repo_path = run_cmd("readlink -f "+src_dir)
    repo_name = repo_path.split("/")[-1]
    db_file = repo_name +".db"
    txl_func_list = repo_name+".function_list.json"
    txl_struct_list = repo_name+".struct_list.json"
    cscope_files = "cscope.files"
    cscope_out = "cscope.out"
    tags_folder = "tags"
    my_bpf_helper_file = "asset/helper_hookpoint_map.json"
    intermediate_f_list = []
    #intermediate_f_list.append(db_file)
    #intermediate_f_list.append(cscope_files)
    intermediate_f_list.append(cscope_out)
    intermediate_f_list.append(tags_folder)
    make_cscope_db(db_file,src_dir,cscope_files,cscope_out,tags_folder)

    txl_dict_func,txl_dict_struct = create_txl_annotation(cscope_files, txl_op_dir)
    if (cmt_op_dir is not None):
        if(args.bpfHelperFile is not None):
            bpf_helper_file = args.bpfHelperFile
        else:
            print("Warning: bpf_helper_file not specified using default asset/helper_hookpoint_map.json\n")
            bpf_helper_file = my_bpf_helper_file
        print(cmt_op_dir)
        create_code_comments(txl_dict_func, bpf_helper_file, cmt_op_dir)
    else:
        print("no comment file found!")

    # run code query to generate annotated function call graph
    create_cqmakedb(db_file, cscope_out, tags_folder)
    if args.annotate_only:
        #clean up
        clean_intermediate_files(intermediate_f_list)
        exit(0)
    
    with open(txl_func_list, "w") as outfile:
        json.dump(txl_dict_func, outfile)
    outfile.close()
    with open(txl_struct_list, "w") as outfile:
        json.dump(txl_dict_struct, outfile)
    outfile.close()
    
    #clean up
    clean_intermediate_files(intermediate_f_list)
