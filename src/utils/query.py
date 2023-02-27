import json
from tinydb import TinyDB
from tinydb import Query

def update_call_depth(human_comments_file,path,func_name,call_depth,match_count):
    func_name = func_name.replace("*","")
    print("UPDATE_CALL_DEPTH: path:  "+path+" func_name: "+func_name+" call_depth: "+str(call_depth))

    cdict = {}
    if human_comments_file == None:
        return cdict
    db = TinyDB(human_comments_file)
    fname = path.split('/')[-1]
    q = Query()
    res = db.search(q.Funcname.search(func_name) & q.File.search(fname))
    if len(res) == 0:
        return
    else:
        print("MATCHING FNS: ")
        print(res)
    match_count = match_count + len(res)
    res = db.update({'call_depth':call_depth},q.Funcname.search(func_name) & q.File.search(fname))
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
    match_count = 0
    #comments_db_file = "/home/palani/github/opened_extraction/op/code_annotation_bu/Katran/boston_katran_comments.json"
    comments_db_file = "/home/palani/github/opened_extraction/op/code_annotation_bu/Cilium/boston_cilium_comments.json"
    comments_db = TinyDB(comments_db_file)
    #fcg_file = "/home/palani/func_level_info/katran.function_file_list.json"
    fcg_file = "/home/palani/func_level_info/cilium.function_file_list.json"
    f = open(fcg_file, "r")   # open the unmodified fcg_file
    json_data = json.load(f)  # parse its JSON
    #print(json_data)
    for func_name in json_data:  # iterate over each entry in the `tag.tg`
        for entry in json_data[func_name]:
            #print(entry['call_depth'])
            update_call_depth(comments_db_file,entry['fileName'],func_name,entry['call_depth'],match_count)
    print("MATCH COUNT: "+str(match_count))
    get_funcs_with_call_depth(comments_db_file,0)
