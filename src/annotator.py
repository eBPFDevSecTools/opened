# Author Info:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

import os
import re
import subprocess
import glob
import shutil
import code_commentor as cmt
import summarizer as sm
import argparse
import json
from collections import defaultdict
from tinydb import TinyDB

def remove_txl_missed_fn(capdict):
    for fn in capdict.keys():
        for en in capdict[fn]:
            if len(list(en['called_function_list'])) == 0:
                continue
            for f in list(en['called_function_list']):
                if f not in capdict.keys():
                    en['called_function_list'].remove(f)
    return capdict

#XXX remove functions which do not have an entry in capdict from the list of called functions??
def add_level_info(capdict):
    q = []
    level_dict = dict()
    map1 = dict()
    map2 = dict()
    cnt =0
    for fn in capdict.keys():
        for en in list(capdict[fn]):
            #print(fn+" calls: "+ str(en['called_function_list']))
            cnt  = cnt +1
            if len(list(en['called_function_list'])) == 0:
                q.append(fn)
            else:
                map2[fn] = len(en['called_function_list'])
                for f in list(en['called_function_list']):
                    if f not in map1:
                        map1[f] = list()
                    map1[f].append(fn)
    level = 0
    while len(q) != 0:
        n = len(q)
        for idx in range(n):
            nd = q.pop(0)
            level_dict[nd] = level
            if nd not in map1:
                continue
            for en in map1[nd]:
                map2[en] = map2[en] - 1
                if map2[en] == 0:
                    q.append(en)
        level = level + 1
    nc = 0
    for fn in capdict.keys():
        if fn not in level_dict:
            continue
        for en in capdict[fn]:
            en['call_depth'] = level_dict[fn]
            nc = nc +1
    print("Found depth for: " + str(nc) + " out of " +str(cnt))

def check_if_cmd_available():
    commands = ['txl', 'cscope', 'ctags', 'cqmakedb']
    for cmd in commands:
        if shutil.which(cmd) is None:
            print("Command: ",cmd," unavailable.. ", "Exiting")
            return False
    #print("All necessary commands found...")
    return True

def check_if_file_available():
    files = [r'asset/txl/c-extract-functions.txl', r'asset/txl/c-extract-struct.txl', r'asset/txl/c.grm', r'asset/txl/bom.grm', r'asset/bpf_helpers_desc_mod.json']
    for fl in files:
        if os.path.isfile(fl) is False:
            print("File: ",fl," unavailable.. ", "Exiting")
            return False
    #print("All necessary asset files found...")
    return True

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
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Running: ",cmd)
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output

def create_directories(dir_list):
    for dr in dir_list:
        if not os.path.exists(dr):
            os.mkdir(dr)

def insert_to_db(db,comment_dict):
    comment_json = json.dumps(comment_dict)
    #print("Inserting comments to DB: "+ comment_json )
    db.insert(comment_dict)


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

# parses output from c-extract-function.txl
def parseTXLFunctionOutputFile(inputFile, func_file_def_dict, isCilium, helperdict):
    iFile = open(inputFile,'r')
    lineCt = 1
    srcSeen=False
    lines = []
    srcFile=""
    for line in iFile.readlines():
        ending = re.match(r"</source",line)
        if ending:
            srcSeen = False;
            #dump to file
            #print(lines)
            lines = []
            continue;
        if srcSeen:
            lines.append(line)
            continue;
        starting = re.match(r"<source",line)
        if starting:
            #print("Starting",line)
            srcSeen = True
            line = line.replace("funcheader","")
            line = line.replace("startline","")
            line = line.replace("endline","")
            line = line.replace(">","")
            line = line.replace("\n","")
            line = line.replace("\"","")
            tokens = line.split('=')
            ##print("len",len(tokens),"tokens",tokens)
            srcFile = tokens[-4]
            srcFile = srcFile.replace(" ","")
            funcName = tokens[-3].replace(" (","(")
            ##print(funcName)
            funcName = funcName.split('(')[-2].split(" ")[-1]
            startLine = int(tokens[-2])
            endLine = int(tokens[-1])
            key=funcName
            fn_def = {}
            fn_def['fileName'] = srcFile
            fn_def['startLine'] = str(startLine)
            fn_def['endLine'] = str(endLine)
            #fn_def['capability'] = sm.get_capability_dict(startLine, endLine, srcFile, helperdict)
            func_file_def_dict[key].append(fn_def)
    return func_file_def_dict

def create_txl_annotation(cscope_file, opdir,func_file_def_dict, map_file_def_dict, isCilium, helperdict):
    print("Read cscope files and generate function annotation ...")
    txl_dict_func_file = {}
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

        #print("File to annotate - ",full_line,"output in",opfile_function_annotate,opfile_struct_annotate)
        op = run_cmd("txl -o "+ opfile_function_annotate+" "+ full_line +" asset/txl/c-extract-functions.txl")
        op = run_cmd("txl -o "+ opfile_struct_annotate +" "+  full_line +" asset/txl/c-extract-struct.txl")
        func_file_def_dict = parseTXLFunctionOutputFile(opfile_function_annotate, func_file_def_dict, isCilium, helperdict)
        map_file_def_dict = parseTXLStructOutputFile(opfile_struct_annotate, map_file_def_dict)
        txl_dict_func_file[full_line] = opfile_function_annotate
    return func_file_def_dict, txl_dict_func_file, map_file_def_dict

def create_cqmakedb(db_file, cscope_file, tags_folder):
    run_cmd("cqmakedb -s "+db_file+" -c "+cscope_file+" -t "+tags_folder+" -p")
    return

def create_code_comments(txl_dict, helperdict, opdir, isCilium, human_comments_file, db_file):
    if(isCilium == False):
        map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
        map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
    else:
        map_update_fn = ["sock_map_update", "map_delete_elem", "map_update_elem","map_pop_elem", "map_push_elem"]
        map_read_fn = ["map_peek_elem", "map_lookup_elem", "map_pop_elem"]

    funcCapDict = dict()
    for srcFile,txlFile in txl_dict.items():
        opFile = opdir+'/'+os.path.basename(srcFile)
        xmlFile = open(txlFile,'r')

        funcCapDict = cmt.parseTXLFunctionOutputFileForComments(xmlFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn, human_comments_file, db_file, funcCapDict)

        xmlFile.close()
    return funcCapDict


# parses output from c-extract-struct.txl
def parseTXLStructOutputFile(fileName, map_file_def_dict):
    iFile = open(fileName,'r')
    lineCt = 1
    inside = False;
    structStr = ""
    for line in iFile.readlines():
        #print(line)
        begin=re.match(r"<struct>",line)
        end = re.match(r"</struct>",line)
        
        if begin:
            startLine = lineCt + 1
            inside = True;
        elif end:
            endLine = lineCt - 1
            key = fileName+":"+str(startLine)+":"+str(endLine);
            inside = False;
            head="//fileName "+fileName+" startLine: "+str(startLine)+" endLine: "+str(endLine)+"\n"
            map_def = {}
            map_def['fileName'] = fileName
            map_def['startLine'] = str(startLine)
            map_def['endLine'] = str(endLine)
            map_file_def_dict[structStr].append(map_def)
            structStr=head+structStr
            structStr= ""
        elif inside == True:
            structStr = structStr + line
        lineCt = lineCt + 1;
    iFile.close()
    return map_file_def_dict
    

if __name__ == "__main__":

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-annotate_only',
            action='store',
            default=False)
    my_parser.add_argument('-s','--src_dir',action='store',required=True,
            help='directory with source code')
    my_parser.add_argument('-o','--txl_op_dir',action='store',required=True,
            help='directory to put txl annotated files')
    my_parser.add_argument('-p','--db_file',action='store',required=True,
            help='sqlite3 db name')
    my_parser.add_argument('-c','--opened_comment_stub_folder',action='store',required=False,
            help='directory to put source files with comment stub')
    my_parser.add_argument('-r','--bpfHelperFile', type=str,required=False,
            help='Information regarding bpf_helper_funcitons ')
    my_parser.add_argument('-t','--txl_function_list',action='store',required=False,
            help='JSON with information regarding functions present. output of foundation_maker.py')
    my_parser.add_argument('-u','--txl_struct_list',action='store',required=False,
            help='JSON with information regarding structures present. output of foundation_maker.py')
    my_parser.add_argument('--isCilium', action='store_true',required=False,
            help='whether repository is cilium')
    my_parser.add_argument('-d','--human_comments_file', action='store',required=False,
            help='JSON with information containing human comments ')

    args = my_parser.parse_args()
    #print(vars(args))
    if(not check_if_cmd_available() or not check_if_file_available()):
       exit(1)

    dir_list = []
    
    isCilium=False
    if(args.isCilium is True):
        isCilium = True
    src_dir = args.src_dir
    if (os.access(src_dir, os.R_OK) is not True):
        print("Cannot read source folder: "+src_dir+" Exiting...")
        exit(1)

    txl_op_dir = args.txl_op_dir
    dir_list.append(txl_op_dir)
    
    cmt_op_dir = None
    if (args.opened_comment_stub_folder is not None):
        cmt_op_dir = args.opened_comment_stub_folder
        dir_list.append(cmt_op_dir)

    human_comments_file = None
    if (args.human_comments_file is not None):
        human_comments_file = args.human_comments_file
        
    create_directories(dir_list)
   
    if (os.access(txl_op_dir, os.W_OK) is not True):
        print("Cannot write to TXL files: "+txl_op_dir+" Exiting...")
        exit(1)
    if (cmt_op_dir is not None and os.access(cmt_op_dir, os.W_OK) is not True):
        print("Cannot write to commented_file dir: "+cmt_op_dir+" Exiting...")
        exit(1)

    repo_path = run_cmd("readlink -f "+src_dir)
    repo_name = repo_path.split("/")[-1]
    db_file = args.db_file +".db"

    
    txl_func_list = repo_name+".function_file_list.json"
    if(args.txl_function_list is not None):
        txl_func_list = args.txl_function_list
    if (os.path.exists(txl_func_list) and os.access(txl_func_list, os.W_OK) is not True):
        print("Cannot read txl_function_list: "+txl_func_list+" Exiting...")
        exit(1)

    txl_struct_list = repo_name+".struct_file_list.json"
    if(args.txl_struct_list is not None):
        txl_struct_list = args.txl_struct_list
    if (os.path.exists(txl_struct_list) and os.access(txl_struct_list, os.W_OK) is not True):
        print("Cannot read txl_struct_list: "+txl_struct_list+" Exiting...")
        exit(1)

    cscope_files = "cscope.files"
    cscope_out = "cscope.out"
    tags_folder = "tags"
    #bpf_helper_file = "asset/helper_hookpoint_map.json"
    bpf_helper_file = "asset/bpf_helpers_desc_mod.json"
    helperdict = sm.load_bpf_helper_map(bpf_helper_file)  
    intermediate_f_list = []
    intermediate_f_list.append(cscope_out)
    intermediate_f_list.append(tags_folder)

    make_cscope_db(db_file,src_dir,cscope_files,cscope_out,tags_folder)
    # run code query to generate annotated function call graph
    create_cqmakedb(db_file, cscope_out, tags_folder)

    txl_dict_struct = defaultdict(list)
    txl_dict_func = defaultdict(list)
    txl_dict_func, txl_func_file, txl_dict_struct = create_txl_annotation(cscope_files, txl_op_dir, txl_dict_func, txl_dict_struct, isCilium, helperdict)
    funcCapDict = dict()
    if (cmt_op_dir is not None):
        comments_db_file = cmt_op_dir+"/"+ db_file +"_comments.db"
        comments_db = TinyDB(comments_db_file)
        if(args.bpfHelperFile is not None):
            bpf_helper_file = args.bpfHelperFile
        funcCapDict = create_code_comments(txl_func_file, helperdict, cmt_op_dir, isCilium, human_comments_file, db_file)
        funcCapDict = remove_txl_missed_fn(funcCapDict)
        add_level_info(funcCapDict)
        for fn in funcCapDict.keys():
            for en in list(funcCapDict[fn]):
                insert_to_db(comments_db, en)
        #insert_to_db(comments_db, funcCapDict)
    else:
        print("no comment file found!")
   
    if args.annotate_only:
        #clean up
        clean_intermediate_files(intermediate_f_list)
        exit(0)

    with open(txl_func_list, "w") as outfile:
        if cmt_op_dir is None:
            json.dump(txl_dict_func, outfile)
        else:
            json.dump(funcCapDict, outfile, indent=2)
    outfile.close()

    with open(txl_struct_list, "w") as outfile:
        json.dump(txl_dict_struct, outfile)
    outfile.close()


    #clean up
    clean_intermediate_files(intermediate_f_list)


