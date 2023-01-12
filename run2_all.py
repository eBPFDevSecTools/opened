import json

#fname = "op/cilium/cilium.function_file_list.json"
#fname = "op/katran/katran.function_file_list.json"
fname = "op/bcc/bcc.function_file_list.json"
func_dict = []

with open(fname) as txl_struct_file:
    func_dict= json.load(txl_struct_file)
    print("TXL_STRUCT_DICT:")
    print(func_dict.keys())
for func_name in func_dict.keys():
    func_details = func_dict[func_name]
    func_name.replace('*','')
    for entries in func_details:
        if(entries["fileName"].endswith(".c")):
            cmd_str = "python3 src/extraction_runner.py -f "+func_name+" -d cilium.db -g op/fcg  -r cilium"
            print(cmd_str)
        else:
            print("#Skipping: "+func_name+" in "+entries["fileName"])