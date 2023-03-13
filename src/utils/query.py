import json
from tinydb import TinyDB
from tinydb import Query
import argparse


def update_call_depth(human_comments_file,path,func_name,call_depth,match_count,version,comments_format):
    func_name = func_name.replace("*","")
    print("UPDATE_CALL_DEPTH: path:  "+path+" func_name: "+func_name+" call_depth: "+str(call_depth))

    cdict = {}
    if human_comments_file == None:
        return cdict
    db = TinyDB(human_comments_file)
    fname = path.split('/')[-1]
    q = Query()
    if comments_format == "old":
        #BU Comments have FuncName
        res = db.search(q.Funcname.search(func_name) & q.File.search(fname))
        if len(res) == 0:
            return
        else:
            print("MATCHING FNS: ")
            print(res)
            match_count = match_count + len(res)
            res = db.update({'call_depth':call_depth},q.Funcname.search(func_name) & q.File.search(fname))
    else:
        #Later versions have funcName
        res = db.search(q.funcName.search(func_name) & q.File.search(fname))
        if len(res) == 0:
            return
        else:
            print("MATCHING FNS: ")
            print(res)
            match_count = match_count + len(res)
            res = db.update({'call_depth':call_depth},q.funcName.search(func_name) & q.File.search(fname))
    print(res)
    return res


def get_funcs_with_call_depth(comments_file,call_depth):
    db = TinyDB(comments_file)
    q = Query()
    res = db.search(q.call_depth == call_depth)
    print("LEN: ")
    print(len(res))
    print(res)
    return res


if __name__ == "__main__":

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-f','--func_depth_file',action='store',required=True,
            help='function list with depth information')
    my_parser.add_argument('-d','--comments_db_file',action='store',required=True,
            help='comments db file')
    my_parser.add_argument('-v','--comments_format',action='store',required=True,choices = ['old','new'], default = 'new',
            help='Format of Human Comments. Allowed options are "old" for BU format and "new" for later versions')
    

    args = my_parser.parse_args()
    print(args)
    
    func_depth_file= args.func_depth_file
    comments_db_file=args.comments_db_file
    comments_format = args.comments_format
    
    #comments_db_file = "/home/palani/github/opened_extraction/op/code_annotation_bu/Cilium/boston_cilium_comments.json"
    #fcg_file = "/home/palani/func_level_info/katran.function_file_list.json"


    comments_db = TinyDB(comments_db_file)
    f = open(func_depth_file, "r")   # open the unmodified fcg_file
    json_data = json.load(f)  # parse its JSON
    #print(json_data)
    match_count=0
    for func_name in json_data:  # iterate over each entry in the `tag.tg`
        for entry in json_data[func_name]:
            #print(entry['call_depth'])
            update_call_depth(comments_db_file,entry['fileName'],func_name,entry['call_depth'],match_count,comments_format)
    print("MATCH COUNT: "+str(match_count))
    get_funcs_with_call_depth(comments_db_file,0)
