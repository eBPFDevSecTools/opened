#Authors:
# Sayandeep Sen (sayandes@in.ibm.com)
# Palani Kodeswaran (palani@in.ibm.com)

import json
import re

def load_bpf_helper_map(fname):
    with open(fname, 'r') as f:
        data = json.load(f)
    return data

def check_and_return_helper_ip(line):
    line = line.replace(")","")
    args = line.split("(")[-1]
    #print("TOK: ",args)
    ip_tokens= args.split(",")
    ret = []
    for val in ip_tokens:
        id1 = val.rfind(' ')
        entry = val[:id1]+" ,Var: "+val[id1+1:]+"}"
        entry = "{Type: "+entry
        ret.append(entry)
    return ret

def enrich_desc_with_input_marking(text,ip_list,helper):
    #print("--->> "+helper)
    for idx,entries in enumerate(ip_list):
        var_name = entries.split(':')[-1].strip()
        var_name = var_name.replace('*','')
        var_name = var_name.replace('}','')
        var_name = ' '+var_name+' '
        replace = " <["+var_name+"]>(IP: "+str(idx)+") "
        #print("var_name:"+var_name+" rep: "+replace)

        # To match ariable names
        text = text.replace(".", ". ")
        text = text.replace(",", " ,")

        text = text.replace(var_name,replace)
    #clean up text before returning    
    #text.strip()
    tokens = text.split()
    print("Text Tok:",tokens)
    temp = ""
    for token in tokens:
        temp = temp + token + " "
    return temp

def build_helper_desc_dict(fname,out,my_dict):
    DELIM="<>"
    ofile = open(out,'w')
    ofile.write("Name,Description,is_map_read,is_map_write\n")
    lines=[]
    dict = {}
    with open(fname,'r') as f:
        for line in f.readlines():
            #line = line.strip()
            text = ""
            #print(line)
            if "Description" in line:
                line.strip()
                if line != "":
                    lines.append(line)
            elif  "              Return" in line: #14 spaces before Return
                ret_line = line.replace("              Return","")
                #print("LINES: ",lines)
                size = len(lines)
                pos = 0
                prev_ret = ""
                for i in range(0,size):
                    line = lines[i]
                    if "Description" in line:
                        helper = lines[i-1]
                        ip_info = check_and_return_helper_ip(helper)
                        if ip_info == None:
                            ip_info_str = "input_args: [],"
                        else:
                            ip_info_str = "input_args: ["+",".join(ip_info)+"]"
                        pos = i;
                        break
                    else:
                        prev_ret = prev_ret+line
                prev_ret = prev_ret.replace(helper,"")
                for i in range(pos+1,size):
                    text = text + lines[i]
                tokens = helper.split("(")[0]
                helper_func = tokens.split()[-1]
                helper_func = helper_func.replace("*","")
                #dict[helper_func] = text
                text = enrich_desc_with_input_marking(text,ip_info,helper_func)
                #print("XXX Helper: ",helper_func," Text: ",text, " Return: ",ret_line)
                ofile.write(prev_ret)
                ofile.write("\n \n \n")
                ofile.write(helper_func+DELIM+ip_info_str+DELIM+text+DELIM+ret_line)
                lines.clear()
            else:
                line = line.strip()
                if line != "":
                    lines.append(line)
    ofile.close()

if __name__ == "__main__":
    fname = './helper_hookpoint_map.json'
    data = load_bpf_helper_map(fname)
    map_update_fn = ["bpf_sock_map_update", "bpf_map_delete_elem", "bpf_map_update_elem","bpf_map_pop_elem", "bpf_map_push_elem"]
    map_read_fn = ["bpf_map_peek_elem", "bpf_map_lookup_elem"]

    build_helper_desc_dict("./man_bpf_helpers.txt","bpf_helpers_desc.txt", data)

