import re
import json
from tinydb import TinyDB

def insert_to_db(db,comment_dict):
    comment_json = json.dumps(comment_dict)
    #print("Inserting comments to DB: "+ comment_json )
    db.insert(comment_dict)

def extract_comments(file_name,start_pattern,end_pattern,db):
    src_file = open(file_name,'r')
    data = src_file.read()
    #print(data)
    #TODO: Try a regular expression insted of multiple split operations
    tokens = data.split(start_pattern)
    for token in tokens[1:]:
        comment = token.split(end_pattern)[0]
        #print(comment)
        op_dict = {}
        op_dict['author']="BU Course Project"
        op_dict['email']="course@bu.edu"
        lines = comment.split('\n')
        #print(lines)
        for line in lines[1:]:
            line_tokens = line.split(':')
            if len(line_tokens) < 2:
                continue
            #print("line_tokens")
            #print(line_tokens)
            key = line_tokens[0]
            value = line_tokens[1]
            op_dict[key] = value
        #print("dict")
        #print(op_dict)
        print(json.dumps(op_dict))
        insert_to_db(db,op_dict)
        
    

if __name__ == "__main__":
    comments_db_file="boston_comments.json"
    comments_db = TinyDB(comments_db_file)
    extract_comments("bpf_lxc.c","OPENED COMMENT BEGIN","OPENED COMMENT END",comments_db)