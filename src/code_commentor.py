import re
import os
import json
import summarizer as smt
import argparse
from collections import defaultdict

def load_bpf_helper_map(fname):
    with open(fname, 'r') as f:
        data = json.load(f)
    return data


def check_and_return_helper_present(my_dict,line):
    for key in my_dict.keys():
        if line.find(key)>=0:
            return key
    return None

def get_helper_encoding(lines,helperdict):
    helper_set= set()
    for line in lines:
        present=check_and_return_helper_present(helperdict,line)
        if present != None:
            helper_set.add(present)
    return list(helper_set)
    #str =  ""
    #for helper in helper_set:
    #    str = str + helper +","
    #return str


def set_to_string(my_set):
    str =  ""
    for elem in my_set:
        str = str + elem +","
    return str


def get_read_maps(lines, map_read_fn):
    map_read_set=set()
    for line in lines:
        mapname= check_map_access(map_read_fn,line)
        if mapname != None:
            map_read_set.add(mapname)
    return set_to_string(map_read_set)
            
def get_update_maps(lines, map_update_fn):
    map_update_set=set()
    for line in lines:
        mapname= check_map_access(map_update_fn,line)
        if mapname != None:
            map_update_set.add(mapname)
    return set_to_string(map_update_set)

def dump_comment(fname,startLineDict, ofname):
    if fname  == "":
        return
    ifile = open(fname,'r')
    #ofname = fname+"-OPENED"
    print("Dumping for: ",fname," outputFile: ",ofname)
    ofile = open(ofname,'w')
    ct = 0
    for line in ifile.readlines():
        ct=ct + 1
        if ct in startLineDict:
            ofile.write(startLineDict.get(ct))
        ofile.write(line)
    ofile.flush()
    ofile.close()
    ifile.close()
            
def check_map_access(my_arr,line):
    for func in my_arr:
        idx = line.find(func)
        if idx>=0:
            chunks = line[len(func)+idx:].replace('(','')
            first_entry_end = chunks.find(',')
            return chunks[:first_entry_end].replace("&","")
    return None



def generate_comment(capability_dict):
    comment="/* \n OPENED COMMENT BEGIN \n"+json.dumps(capability_dict,indent=2)+" \n OPENED COMMENT END \n */ \n"
    return comment


# parses output from c-extract-function.txl
def parseTXLFunctionOutputFileForComments(inputFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn, isCilium):
    srcSeen=False
    lines = []
    startLineDict ={}
    funcName=""
    funcArgs=""
    output=""
    startLine = -1
    endLine = -1
    for line in inputFile.readlines():
        ending = re.match(r"</source",line)
        if ending:
            srcSeen = False;
            #dump to file
            #print(lines)
            encoding = get_helper_encoding(lines,helperdict)
            read_maps=get_read_maps(lines, map_read_fn)
            update_maps=get_update_maps(lines, map_update_fn)
            #print("funcName: ",funcName," srcFile: ",srcFile)
            capability_dict = smt.get_capability_dict(startLine, endLine, srcFile, isCilium, None)
            capability_dict['startLine'] = startLine
            capability_dict['endLine'] = endLine
            capability_dict['File'] = srcFile
            capability_dict['Funcname'] = funcName
            capability_dict['Update_maps'] = update_maps.split(",")
            capability_dict['Read_maps'] = read_maps.split(",")
            capability_dict['Input'] = funcArgs.split(',')
            capability_dict['Output'] = output
            capability_dict['Helper'] = encoding
            func_desc_list = []
            empty_desc = {}
            empty_desc['description'] = ""
            empty_desc['author'] = ""
            empty_desc['author_email'] = ""
            empty_desc['date'] = ""

            func_desc_list.append(empty_desc)
            capability_dict['human_func_description'] = func_desc_list
            empty_desc_auto = {}
            empty_desc_auto['description'] = ""
            empty_desc_auto['author'] = ""
            empty_desc_auto['author_email'] = ""
            empty_desc_auto['date'] = ""
            empty_desc_auto['params'] = ""
            ai_func_desc_list = []
            ai_func_desc_list.append(empty_desc_auto)
            capability_dict['AI_func_description'] = ai_func_desc_list
            #comment = generate_comment(srcFile,funcName,startLine,endLine,funcArgs,output,encoding,read_maps,update_maps, capability_dict)
            comment = generate_comment(capability_dict)
            #dump_comment(srcFile,startLine,comment)
            
            startLineDict[startLine] = comment
            #print(comment)
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
            #print("len",len(tokens),"tokens",tokens)

            funcHeader=tokens[2]
            #print("funcHeader: ",funcHeader)
            funcArgs = funcHeader.split('(')[-1]
            funcArgs = funcArgs.split(')')[0]
            #funcArgs = funcArgs.replace(" ","")
            #print("args ",funcArgs)
            if(funcArgs is None or not funcArgs or funcArgs.isspace() is True):
                funcArgs = "NA"

            
            srcFile = tokens[-4]
            srcFile = srcFile.replace(" ","")

            funcName = tokens[-3].replace(" (","(")
            #print("funcName: ",funcName)
            #print("funcName.split('(')[-2]: ",funcName.split('(')[-2])
            output= " ".join(funcName.split('(')[-2].split(" ")[:-1])
            output = output.replace(" ","")
            if(output is None or not output or output.isspace() is True):
                output = "NA"
            funcName = funcName.split('(')[-2].split(" ")[-1]

            startLine = int(tokens[-2])
            endLine = int(tokens[-1])
            #print("File: ",srcFile, " startline: ",startLine," endline: ",endLine," funcname: ",funcName, "Input: (", funcArgs, ") Output: ",output)
            #key=funcName+":"+srcFile+":"+str(startLine)
            key=funcName+":"+srcFile
            #print("Checking if need to extract",key
    if srcFile != "":
        #print("Going to call dump_comment for: "+srcFile)
        #print(startLineDict)
        dump_comment(srcFile,startLineDict, opFile)

        
        #print("XML: ",inputFile," StartLineDict: ",startLineDict)

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description='Code commentor')
    parser.add_argument('-o','--opFile', type=str,required=True,
            help='output file to dump commented code ')

    parser.add_argument('-f','--bpfHelperFile', type=str,required=True,
            help='Information regarding bpf_helper_funcitons ')

    parser.add_argument('-i','--txlFile', type=str,required=True,
            help='TXL annotated files with function and map listings')

    parser.add_argument('-s','--srcFile', type=str,required=True,
            help='eBPF code file')

    parser.add_argument('-c','--isCilium', type=bool,required=True,
            help='whether repository is cilium')


    args = parser.parse_args()

    print("Args",args)

    opFile=args.opFile
    srcFile=args.srcFile
    txlFile=args.txlFile
    isCilium=args.isCilium
    if txlFile.endswith(".xml"):
        bpf_helper_file= args.bpfHelperFile #'./helper_hookpoint_map.json'
        startLineDict = {}
        helperdict = load_bpf_helper_map(bpf_helper_file)
        if(isCilium == False):
            map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
            map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem", "bpf_map_pop_elem"]
        else:
            map_update_fn = ["sock_map_update", "map_delete_elem", "map_update_elem","map_pop_elem", "map_push_elem"]
            map_read_fn = ["map_peek_elem", "map_lookup_elem", "map_pop_elem"]

        xmlFile = open(txlFile,'r')
        parseTXLFunctionOutputFileForComments(xmlFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn, isCilium)
        xmlFile.close()
        '''
        ifile = open("./txl_annotate/annotate_func_test_decap_kern.c.xml",'r')
        parseTXLFunctionOutputFileForComments(ifile)
        ifile.close()
        '''
