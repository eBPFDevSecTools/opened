# Author Info:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)
# License: TBD

import os
import re
import subprocess
import glob
import command
import shutil
#import code_commentor as cmt
import argparse
from collections import defaultdict

def check_if_cmd_available():
    commands = ['txl', 'cscope', 'ctags', 'cqmakedb', 'cqsearch']
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
        print("Failed while running: ",cmd," Exiting...")
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

#does structStr contain map name that is of interest
def doesStructContainMap(str):
    for key in maps:
        print("Checking if MOI: "+key)
        #isMap = re.match(key,str)
        if key in str.split():
            print("MOI: map_name:  "+key+" struct: "+str)
            return (True,key)
        
    return (False,None)


# parses output from c-extract-struct.txl
def parseTXLStructOutputFile(fileName):

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
            (isMap,mapName) = doesStructContainMap(structStr)
            if isMap == True:
                head="//fileName "+fileName+" startLine: "+str(startLine)+" endLine: "+str(endLine)+"\n"
                structStr=head+structStr
                opMaps[mapName].add(structStr)
                map_def = fileName +":"+str(startLine)+":"+str(endLine)
                map_file_def_dict[mapName].add(map_def)
        
            structStr= ""
        elif inside == True:
            structStr = structStr + line
        lineCt = lineCt + 1;
    iFile.close()
    
    
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
                

def search_function(function_name, db_file):
    print("Running cqsearch for ",function_name," and outputting dependencies to func.out")
    status=run_cmd("cqsearch -s "+db_file+" -t "+function_name+"  -p 7  -l 100 -k 10 -e -o func.out")
    base_dir = os.getcwd()
    cmd_str=" sed -i  -e \"s|\$HOME|"+base_dir+"|g\" func.out"
    status=run_cmd(cmd_str)

if __name__ == "__main__":

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-annotate_only',
            action='store',
            default=False)
    my_parser.add_argument('-f','--function_name',action='store',required=True)
    my_parser.add_argument('-s','--src_dir',action='store',required=True)
    my_parser.add_argument('-o','--txl_op_dir',action='store',required=True)

    args = my_parser.parse_args()
    print(vars(args))
    if(not check_if_cmd_available() or not check_if_file_available()):
        exit(1)
    dir_list = []
    db_file = "test.db"
    cscope_files = "cscope.files"
    cscope_out = "cscope.out"
    tags_folder = "tags"
    intermediate_f_list = []
    intermediate_f_list.append(db_file)
    #intermediate_f_list.append(cscope_files)
    intermediate_f_list.append(cscope_out)
    intermediate_f_list.append(tags_folder)
    
    function_name= args.function_name
    src_dir = args.src_dir
    txl_op_dir = args.txl_op_dir
    dir_list.append(txl_op_dir)
    create_directories(dir_list)
    make_cscope_db(db_file,src_dir,cscope_files,cscope_out,tags_folder)

    txl_dict_func,txl_dict_struct = create_txl_annotation(cscope_files,txl_op_dir)
    if args.annotate_only:
        #clean up
        clean_intermediate_files(intermediate_f_list)
        exit(0)
    
    structFiles = []
    opMaps=defaultdict(set)
    map_file_def_dict=defaultdict(set)
    maps = {}
    dup_map_dict = defaultdict(list)
    extracted_files = []

    # run code query to generate annotated function call graph
    create_cqmakedb(db_file, cscope_out, tags_folder)
    search_function(function_name, db_file)

    # Read set of maps to be extracted to check for duplicate map definitions 
    ifile = open('func.out','r')
    parseFunctionList(ifile)
    ifile.close()

    #Parse TXL annotated files
    for fName in txl_dict_struct.values():
        print("annotatedFile: ",fName)
        parseTXLStructOutputFile(fName)

    #get duplicate map definitions
    for map_name in map_file_def_dict:
        if len(map_file_def_dict[map_name]) > 1:
            for map_def in map_file_def_dict[map_name]: 
                dup_map_dict[map_name].append(map_def)

    # Write duplicate map definitions to func.out
    out = open("func.out",'a')
    out.write("#DUPLICATE MAP DEFNS\n{#map_name,file_locations\n")

    for map_name in dup_map_dict:
        line = map_name +","+ str(len(dup_map_dict[map_name]))
        for header  in dup_map_dict[map_name]:
            tokens = header.split(":")
            fname = tokens[0]
            startLine = tokens[1]
            line = line + ",["+fname+","+startLine+"]"
        out.write(line)
        out.write("\n")
        

    out.write("}\n")
    out.close()

    #clean up
    #clean_intermediate_files(intermediate_f_list)

    
    
