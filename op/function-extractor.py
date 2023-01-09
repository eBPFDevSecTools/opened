#Author Info: 
# Palani Kodeswaran (palani.kodeswaran@in.ibm.com)
# Sayandeep Sen (sayandes@in.ibm.com)
import json
import subprocess
import re
import os.path
import os
import shutil
from collections import defaultdict
from collections import OrderedDict
import argparse

def run_cmd(cmd):
    print("Running: ",cmd)
    status, output = subprocess.getstatusoutput(cmd)
    if(status != 0):
        print("Failed while running: ",cmd,"Message: ",output, " Exiting...")
        exit(1)
    return output


def dump_to_file(f,appt):
    str = "//" + appt.get('file')+ " " + appt.get('startline')+ " "+ appt.get('endline') + " \n"
    f.write(str)
    f.write(appt.text)

def copyMakefile(srcdir,opdir):
    isExist = os.path.exists(opdir) and os.path.exists(opdir) 
    if isExist:
        path= srcdir+"/"+'Makefile'
        makeExist = os.path.exists(path)
        if makeExist:
            shutil.copy(path,opdir)
        else:
            print("Makefile does not exist in ",srcdir)
            exit(1)
    else:
        print("One or More directories do not exist")
        exit(1)
    

    
def make_extraction_dir(path):
    # Check whether the specified path exists or not
    isExist = os.path.exists(path)

    if isExist:
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))
    # Create a new directory because it does not exist 
    else:
        os.makedirs(path)
        print("The new directory is created!")
    #os.chdir(path)
# string to search in file

def create_preprocessor_map(filename):

    fp = open(filename, 'r')
        # read all lines using readline()
    lc = 1
    lines = fp.readlines()
    #print("Creating preprocessor for: ",filename)
    stack = []
    pres=[]

    for line in lines:
        # check if string present on a current line
        ifdefstring = '#ifdef '
        ifstring = '#if '
        elsestring = '#else '
        endifstring = '#endif '
        elifstring = '#elif '
        ifndefstring = '#ifndef '
        # find() method returns -1 if the value is not found,
        # if found it return 0
        if line.find(ifdefstring) == 0:
            print('string #ifdef exists in file')
            #print('line Number:', lc,line)
            tokens = line.split()
            name = tokens[1]
            stack.append((ifdefstring,name,lc))

        if line.find(ifstring) == 0:
            #print('string #if exists in file')
            #print('line Number:', lc,line)
            tokens = line.split()
            name = tokens[1]
            stack.append((ifstring,name,lc))


        if line.find(ifndefstring) == 0:
            #print('string #ifndef exists in file')
            #print('line Number:', lc,line)
            tokens = line.split()
            name = tokens[1]
            stack.append((ifndefstring,name,lc))


        if line.find(elifstring) == 0:
           #print('string #elif exists in file')
           #print('line Number:', lc,line)
           (t,name,bg) = stack.pop()
           pres.append((t,name,bg,lc-1))
           tokens = line.split()
           stack.append((ifdefstring,tokens[1],lc))

        if line.find(elsestring) == 0:
           #print('string #else exists in file')
           #print('line Number:', lc,line)
           (t,name,bg) = stack.pop()
           pres.append(( t,name,bg,lc-1))
           tokens = line.split()
           stack.append((ifndefstring,name,lc))


        if line.find(endifstring) == 0:
           #print('string #endif exists in file')
           #print('line Number:', lc,line)
           (t,name,bg) = stack.pop()
           pres.append(( t,name,bg,lc-1))

        lc = lc + 1

    #print(pres)       
    return pres

# checks if function/struct in filename between st_line and end_line needs to be guarded with IFDEF MACROS
def contained_in_preprocessor(fname, pres, st_line, end_line):
        print("checking containment in: ",fname,"start: ",st_line,"end: ",end_line)
        for (t,defName,start,end) in pres:
                if int(st_line) >= int(start) and int(end_line) <= int(end):
                    #print("Fully contained ", t, defName)
                    return (t,defName,start,end)
        return (None,None,None,None)
                    
# reads cscope.files and copies headers to directory Also adds headers to headers dict
#./examples/cilium/include/bpf/... 
def copy_include_files(iFile, opdir,base_dir):
    iFilePtr = open(iFile,'r')
    for line in iFilePtr.readlines():
        print("cscope header: ",line)
        line=line.replace("\n","")
        if line.endswith(".h"):
            full_line = run_cmd("readlink -f "+line) 
            header_path= full_line.split(base_dir)[-1]
            dir_name= opdir+"/"+header_path
            print("dir_name: "+dir_name)
            os.makedirs(os.path.dirname(dir_name), exist_ok=True)
            shutil.copy(line,dir_name)
            #headers[line]=1
            #print("copying header: ",line)
    #shutil.copy("Makefile",opdir)
    iFilePtr.close()

# read iFile from startLine to endLine and writes to oFile
def extractAndDump(iFile,startLine,endLine,oFile):
    ##print("iFile",iFile, "startline:",startLine," endline: ",endLine)
    if not os.path.exists(iFile):
        #print("File Not Found: ",iFile)
        return
    val=None
    #check if we need to guard this func/struct with a macro
    p = presDict[iFile]
    if not p:
        print("ALERT: PREPROCESSING DICT MISSING FOR: ",iFile)
    else:
        (val,name,start,end) = contained_in_preprocessor(iFile,p, startLine, endLine)
    if val:
        cmd = val+" "+name+"\n"
        oFile.write(cmd)
    iFilePtr = open(iFile,'r')
    lineCt = 1
    #ignore lines
    while lineCt < startLine:
        ##print("skipping line#: ",lineCt)
        iFilePtr.readline()
        lineCt = lineCt + 1;
    comment = "/* Extracted from \n "+ iFile+ " \n startLine: "+ str(startLine) + " endLine: "+ str(endLine) + "\n */ \n"
    oFile.write(comment)
    while lineCt <= endLine :
        line = iFilePtr.readline()
        ##print("lineCt",lineCt, " line: ",line)
        oFile.write(line)
        lineCt= lineCt + 1
            
    iFilePtr.close()
    if val:
        cmd="#endif \n"
        oFile.write(cmd)
    return

#does structStr contain map name that is of interest
def doesStructContainMap(str,maps):
    for key in maps:
        #isMap = re.match(key,str)
        if key in str.split():
            return (True,key)
        
    return (False,None)

def dumpFns(f,e):
    for key in fns:
        (funcName,srcFile,startLine,endLine) = fns[key]
        if not funcName == None and not srcFile.endswith(".h"):
            op=funcName+","+srcFile+",["+str(startLine)+":"+str(endLine)+"]\n"
            e.write(op)
            extractAndDump(srcFile,int(startLine),int(endLine),f)
            #del fns[key]

# Check if struct definition could be an eBPF map definition based on map name
def extract_maps_from_struct_defs(txl_struct_dict,fcg_maps,op_maps,extract_defines_files_set):
    for structStr in txl_struct_dict:
        print("structStr: "+structStr)
        struct_defn_list = txl_struct_dict[structStr]
        print("struct_defn_list: ")
        print(struct_defn_list)
        for struct_defn in struct_defn_list:
            print("struct_defn: "+str(struct_defn))
            struct_defn_dict  = struct_defn
            #struct_defn_dict = json.loads(struct_defn)
            fileName = struct_defn_dict["fileName"]
            startLine = struct_defn_dict["startLine"]
            endLine = struct_defn_dict["endLine"]
            if not fileName in presDict:
                p = create_preprocessor_map(fileName)
                presDict[fileName]=p
            (isMap,mapName) = doesStructContainMap(structStr,fcg_maps)
            if isMap == True:
                head="//fileName "+fileName+" startLine: "+str(startLine)+" endLine: "+str(endLine)+"\n"
                print("STRUCT: "+mapName+ "  IS MAP: "+head+"\n\n")
                structStr=head+structStr
                op_maps[mapName].append(structStr)
                #Add defines for cilium map defns coming from .c files
                if fileName.endswith(".c"):
                    extract_defines_files_set.add(fileNmae)
                    

def build_fn_list_to_extract(txl_func_dict,fcg_fns,extract_defines_files_set):
    for func_name in txl_func_dict:
        func_defn_list = txl_func_dict[func_name]
        print("func_defn_list: ")
        print(func_defn_list)
        for func_defn in func_defn_list:
            func_defn_dict = func_defn
            #func_defn_dict = json.loads(func_defn)
            fileName = func_defn_dict["fileName"]
            startLine = func_defn_dict["startLine"]
            endLine = func_defn_dict["endLine"]
            if not fileName in presDict:
                p = create_preprocessor_map(fileName)
                presDict[fileName]=p
            key=func_name+":"+fileName
            #print("Checking if need to extract",key)
            if key in fcg_fns.keys():
                fcg_fns.update({key:(func_name,fileName,startLine,endLine)})
                if not fileName.endswith(".h"):
                    print("Need to Extract Function", key)
                #TODO:DO not include duplicate #defines
                if fileName.endswith(".c"):
                    extract_defines_files_set.add(fileName)
                    


# read cFile and included headers to headers dict
def addDependsOn(cFile):
    with open(cFile) as iFile:
        for line in iFile.readlines():
            if "#include" in line:
                h  = line.split()[-1]
                #h = h.replace("<","")
                #h = h.replace(">","")
                h = h.replace("\"","")
                ##print("cFile: ",cFile," h: ",h)
                graph[h].add(cFile)
                #print("Adding Header Dep: From",cFile," to: ",h )
                #headers[h]=1
                headers[h] = cFile
               
    iFile.close()

#dump #defines to output file
def addDefines(cFile,ofile,preprocessor_names,dup_preprocessor_names):
    full_line = run_cmd("readlink -f "+cFile) 
    with open(full_line) as iFile:
        multi = False
        cont_char = ''
        lineCt=0
        for line in iFile.readlines():
            lineCt = lineCt + 1
            sline = line.rstrip()
            if len(sline) > 0:
                cont_char = sline[-1]
            else:
                continue #empty line
            if "#define" in line:
                line_arr=line.split("#define")
                tokens = line_arr[1].split()
                var_name=tokens[0]
                if var_name in preprocessor_names.keys():
                    print("DUPLICATE #define "+var_name+" cFile: "+cFile+" lineCt: "+str(lineCt))
                    dup_preprocessor_names[var_name]=1
                else:
                    preprocessor_names[var_name]=1

                cont_char = sline[-1]
                ofile.write("//OPENED COMMENT BEGIN: From: "+full_line+" startLine: "+str(lineCt)+"\n")
                ofile.write("#ifndef "+var_name+"//OPENED define "+var_name+" BEG\n")

                if cont_char=='\\':#"\\" in line:
                    multi = True;
                    ofile.write(line)
                else :
                    ofile.write(line)
                    ofile.write("#endif //OPENED define "+var_name+" END\n\n")
                    ofile.write("//OPENED COMMENT END : From: "+full_line+" endLine: "+str(lineCt)+"\n\n")
            elif cont_char == '\\' and multi == True:
                ofile.write(line)
                #print( line+" XXXXX "+line[-1]+"\n")
            elif cont_char != '\\' and multi == True: 
                ofile.write(line+"\n")
                ofile.write("#endif //OPENED define "+var_name+" END\n\n")
                ofile.write("//OPENED COMMENT END: From: "+full_line+" endLine: "+str(lineCt)+"\n\n")
                #print("no \\ "+line+" XXXXX ["+line[-2]+"]\n")
                multi = False

    iFile.close()
    
#TODO: Remove this function or addDependsOn
#buildIncludesOrderingGraph
def buildIncludesOrderingGraph(cFile):
    with open(cFile) as iFile:
        for line in iFile.readlines():
            if "#include" in line:
                h  = line.split()[-1]
                h = h.replace("<","")
                h = h.replace(">","")
                h = h.replace("\"","")
                print("cFile: ",cFile," h: ",h)
                
                
                
               
    iFile.close()

def processFuncLine(line,fns):
    ###print("Processing", line)
    line = line.replace('[','')
    line = line.replace(']','')
    tokens = line.split(',')
    fnName = tokens[0]
    count = tokens[1]
    if int(count) > 1:
        ##print("Duplicate Defns: ", line);
        duplicates.append(line)
        return
    src = tokens[2]
    #Add headers included by .c files only
    if src.endswith(".c"):
        addDependsOn(src)
    startLine = tokens[3]
    #remove end ]
    startLine = startLine[:-1]
    ##print(fnName,count,src,startLine)
    #key=fnName+":"+src+":"+startLine
    key=fnName+":"+src
    fns[key]=(None,None,None,None)

def processMapLine(line,maps):
    print("Processing", line)
    line = line.replace('[','')
    line = line.replace(']','')
    tokens = line.split(',')
    mapName = tokens[0]
    srcFile = tokens[1]
    if srcFile.endswith(".h"):
        print("")
        #Commentged for Checking: Dec 7
        #headers[srcFile]=1
        #addDependsOn(srcFile)
    startLine = tokens[2]
    isFound = tokens[3]
    ##print(fnName,count,src,startLine)
    #key=fnName+":"+src+":"+startLine
    key=mapName
    maps[key]=1


# Parses output from codequery search output and puts in map
def parseFunctionCallGraph(ifile,fns,maps):
    ct = 0
    for line in ifile.readlines():
        ##print(line)
        m = re.match(r"[{}]",line)
        if m:
            #print("Ignoring",line)
            ct = ct + 1
        else:
            #print("ct",ct)
            if ct < 2:
                processFuncLine(line,fns)
            elif ct > 2 and ct < 4:
                processMapLine(line,maps)
            else:
                print("TODO: PROCESS DUPLICATE MAP DEFNS..IGNORE FOR NOW")

            
if __name__ == "__main__":

 
    parser = argparse.ArgumentParser(description='Function Extractor')
    parser.add_argument('-o','--opdir', type=str,required=True,
                    help='directory to dump extracted files to ')

    parser.add_argument('-c','--codequeryOutputFile', type=str,required=True,
                    help='Function and Map dependency output from codequery ')

    parser.add_argument('-e','--extractedFileName', type=str,required=True,
                    help='Output file with extracted function')

    parser.add_argument('-t','--struct_info', type=str,required=True,
                    help='json file containing struct definitions in the repo')

    parser.add_argument('-f','--func_info', type=str,required=True,
                    help='json file containing function definitions in the repo')

    parser.add_argument('-s','--srcdir', type=str,required=True,
                    help='Directory containing source files for function  to be extraced from')

    parser.add_argument('-b','--basedir', type=str,required=True,
                    help='Base Directory path relative to which directory structure in opdir will be created')

    parser.add_argument('--isCilium', action='store_true',required=False,
            help='whether repository is cilium')

    
    args = parser.parse_args()

    print("Args",args)
    isCilium=False
    if(args.isCilium is True):
        isCilium = True


    opdir=args.opdir
    codequeryOutputFile=args.codequeryOutputFile
    extractedFileName = opdir+"/"+args.extractedFileName

    struct_info =args.struct_info
    func_info =args.func_info
    srcdir = args.srcdir
    basedir=args.basedir

    cscopeFile="./cscope.files"
    dupFileName=opdir+"/"+"duplicates.out"
    extractedFunctionListFile="extractedFuncList.out"
    
    #dict containing function definitions
    #fns = {}
    fns = OrderedDict()
    
    # dict containing dupcliate fn definitions
    duplicates = []

    #dict contatining header files
    headers = {}

    #dict containing header file dependencies for ordering includes in final generated file
    graph = defaultdict(set)

    #dict containing map defns to be extracted
    maps = {}

    #dict containing maps that will be written out
    opMaps = defaultdict(list)

    #dict of dict containing pre processor directives per file
    presDict = defaultdict(list)

    #list of c files from which to include #defines
    extract_defines_files_set = set()

    #dict containing duplicate #defines
    preprocessor_names={}
    dup_preprocessor_names = {}

    make_extraction_dir(opdir)
    copy_include_files(cscopeFile, opdir,basedir)
    copyMakefile(srcdir,opdir)

    dupFile = open (dupFileName,'w')
    ifile = open(codequeryOutputFile,'r')
    eFile = open(extractedFunctionListFile,'w')
    f = open(extractedFileName,'w')

    parseFunctionCallGraph(ifile,fns,maps)
    ifile.close()

    
    #include required header files
    f.write("/* SPDX-License-Identifier: GPL-2.0 */\n");
    f.write("#define RECORD_FLOW_INFO\n")
    
    
    with open(struct_info) as txl_struct_file:
        txl_struct_dict= json.load(txl_struct_file)
        print("TXL_STRUCT_DICT:")
        print(txl_struct_dict)


    with open(func_info) as txl_func_file:
        txl_func_dict = json.load(txl_func_file)
        print("TXL_FUNC_DICT:")
        print(txl_func_dict)

    extract_maps_from_struct_defs(txl_struct_dict,maps,opMaps,extract_defines_files_set)
    build_fn_list_to_extract(txl_func_dict,fns,extract_defines_files_set)
    for c_file in extract_defines_files_set:
        addDefines(c_file,f,preprocessor_names,dup_preprocessor_names)
    
    ##print("HEADERS\n")
    for header in headers.keys():
        orig = header
        ##print(header)
        if not "<" in header:
            header = header.split('/')[-1]
            macro = header.upper()
            macro = macro.replace(".","_")
            macro = macro.replace("/","_")
            macro = macro.replace("-","_")
            macro = macro + "_OPENED_FRAMEWORK"
            cmd = "#ifndef "+ macro + "\n"
            cmd += "#define " + macro + "\n"
            #cmd += "#include \"" + header + "\"\n"
            cmd += "#include \"" + orig + "\"\n"
            cmd += "#endif \n\n"
        else:
            cmd = "#include " + header + "\n"
        f.write(cmd)
        f.write("//OPENED: included from: "+headers[orig]+ "\n\n")

    for mapName  in opMaps:
        isDup=False
        if len(opMaps[mapName]) > 1:
            isDup=True
            cmd = "//ATTENTION BEGIN: DUPLICATE MAP DEFNS\n"
            f.write(cmd)
        for s in opMaps[mapName]:
            # Do not write structs from .h files as they will already be included
            if not ".h" in s:
                f.write(s)
            else:
                if isDup == True:
                    f.write("//DUP Defn at: ")
                    h = s.split("\n")[0]
                    h = h.replace("//","")
                    f.write(h)
                    f.write("\n")
        if isDup == True:
            f.write("//ATTENTION END \n")
            isDup=False;

        
    dumpFns(f,eFile)
    if isCilium:
        f.write("BPF_LICENSE(\"Dual BSD/GPL\");");
    else:
        f.write("char _license[] SEC(\"license\") = \"GPL\";");
    
    f.close()
    eFile.close()

    print("DUPLICATE #Defines")
    for name in dup_preprocessor_names.keys():
        print(name)
    
    print("MAPS\n")
    for mapName  in opMaps:
        if len(opMaps[mapName]) > 1:
            print("DUPLICATE MAP",mapName)
        else:
            print("MAP",mapName)
    
    
    for dup in duplicates:
        dupFile.write(dup)
    dupFile.close()

