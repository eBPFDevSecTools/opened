import re
import json
from tinydb import TinyDB
from datetime import date
import argparse
import glob
import os
from tinydb import Query
from tinydb.operations import set

ai_func_desc_key = "AI_func_description"

def update_ai_func_description(comments_db,comment_dict):
    funcName = comment_dict['funcName']
    #remove * from function name
    funcName = funcName.replace("*","")
    file_name = comment_dict['File']
    fname = file_name.split('/')[-1]
    startLine = comment_dict['startLine']

    q = Query()
    print("Checking funcName: "+funcName+" fname: "+fname+ " file_name: "+file_name)
    res = comments_db.search(q.funcName.search(funcName) & q.File.search(fname))
    #res = comments_db.search(q.funcName.search(funcName))
    print("Query Result1: " + str(len(res)))
    print(res)
    c = []
    c.append(comment_dict)

    for e in res:
        print(e['funcName'])
        ai_descs = e[ai_func_desc_key]
        print("AI Descs: "+ str(len(ai_descs)))
        print(ai_descs)
        if(len(ai_descs) == 1) :
            desc = ai_descs[0]
            print("desc: ")
            print(desc)
            #if desc == None or desc == "{}":
            #Fix if for None
            comments_db.update(set(ai_func_desc_key,c),(Query().funcName.matches(funcName))  & (Query().File.search(fname)))
            print("UPDATED")
            continue
        else:
            #check if description is empty
            #human_descs.append(json_str)
            ai_descs.append(comment_dict)
            comments_db.update(set(ai_func_desc_key,ai_descs),(Query().funcName.matches(funcName))  & (Query().File.search(fname))  )
            print("UPDATED")

            
    print("VALIDATING")
    res = comments_db.search(q.funcName.search(funcName) & q.File.search(fname) )
    #res = comments_db.search(q.funcName.search(funcName))
    print("Query REsult2: " + str(len(res)))
    print(res)
    for e in res:
        print(e['funcName'])
        print(e[ai_func_desc_key])


if __name__ == "__main__":
    #comments_db_file = "./katran.db_comments.db"
    comments_db_file ="./bpf-filter-master.db_comments.db"
    #comments_db_file="../../op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db"
    comments_db = TinyDB(comments_db_file)
    print("LEN: "+str(len(comments_db)))
    res = comments_db.all()
    #print(res)

    q = Query()
    #funcName = "encap_v6"
    funcName = "bpf_filter"
    File = "/home/palani/github/opened_extraction/examples/bpf-filter-master/ebpf/drop.c"
    #res = comments_db.search(Query().funcName.matches("compare_mac"))
    #res = comments_db.search(Query().funcName.matches("is_under_flood"))
    res = comments_db.search(Query().funcName.matches(funcName))

    

    print(len(comments_db))
    #print(comments_db.all())
    c = []
    c_dict ={}
    c_dict['funcName'] = funcName
    c_dict['File'] = File
    c_dict['startLine'] = 90
    c_dict['description'] = "IRL ADDED"
    c_dict['author'] = "IRL"
    c_dict['authorEmail'] = "irl@ibm.com"
    c_dict['date'] = "16/3/2023"
    c_dict['invocationParameters'] = "name=GPT3,max_length=200, version=1"
    c.append(c_dict)
    update_ai_func_description(comments_db,c_dict)



