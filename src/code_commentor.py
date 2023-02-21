#Authors:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani@in.ibm.com)

import re
import os
import json
import summarizer as smt
import argparse
from collections import defaultdict
from tinydb import TinyDB
import utils.comment_extractor as extractor

def insert_to_db(db,comment_dict):
    comment_json = json.dumps(comment_dict)
    #print("Inserting comments to DB: "+ comment_json )
    db.insert(comment_dict)


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


def generate_comment(capability_dict):
    return "/* \n OPENED COMMENT BEGIN \n"+json.dumps(capability_dict,indent=2)+" \n OPENED COMMENT END \n */ \n"


# parses output from c-extract-function.txl
def parseTXLFunctionOutputFileForComments(inputFile, opFile, srcFile, helperdict, map_update_fn, map_read_fn, isCilium,comments_db,human_comments_file):
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
            #print("funcName: ",funcName," srcFile: ",srcFile)
            capability_dict = smt.get_capability_dict(startLine, endLine, srcFile, isCilium, None)
            capability_dict['startLine'] = startLine
            capability_dict['endLine'] = endLine
            capability_dict['File'] = srcFile
            capability_dict['funcName'] = funcName
            capability_dict['updateMaps'] = smt.get_update_maps(lines, map_update_fn)
            capability_dict['readMaps'] = smt.get_read_maps(lines, map_read_fn)
            capability_dict['input'] = funcArgs.split(',')
            capability_dict['output'] = output
            capability_dict['helper'] = smt.get_helper_list(lines,helperdict)
            capability_dict['compatibleHookpoints'] = smt.get_compatible_hookpoints(capability_dict['helper'] , helperdict)
            capability_dict['source'] = lines
            func_desc_list = []
            human_description = extractor.get_human_func_description(human_comments_file,srcFile)
            empty_desc = {}
            empty_desc['description'] = ""
            empty_desc['author'] = ""
            empty_desc['authorEmail'] = ""
            empty_desc['date'] = ""

            func_desc_list.append(empty_desc)
            func_desc_list.append(human_description)
            capability_dict['humanFuncDescription'] = func_desc_list
            empty_desc_auto = {}
            empty_desc_auto['description'] = ""
            empty_desc_auto['author'] = ""
            empty_desc_auto['authorEmail'] = ""
            empty_desc_auto['date'] = ""
            empty_desc_auto['invocationParameters'] = ""
            ai_func_desc_list = []
            ai_func_desc_list.append(empty_desc_auto)
            capability_dict['AI_func_description'] = ai_func_desc_list
            #comment = generate_comment(srcFile,funcName,startLine,endLine,funcArgs,output,encoding,read_maps,update_maps, capability_dict)
            comment = generate_comment(capability_dict)
            insert_to_db(comments_db,capability_dict)
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
        helperdict = smt.load_bpf_helper_map(bpf_helper_file)
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
