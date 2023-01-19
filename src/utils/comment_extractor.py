import re
import json
from tinydb import TinyDB
from datetime import date
import argparse
import glob

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
        op_dict['authorEmail']="course@bu.edu"
        op_dict['date']= str(date.today())
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
    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-s','--src_dir',action='store',required=True,
            help='directory with source code')
    my_parser.add_argument('-d','--comments_dbfile',action='store',required=True,
            help='comments db file')
    args = my_parser.parse_args()
    src_dir = args.src_dir
    comments_db_file=args.comments_dbfile
    #comments_db_file="boston_comments.json"
    comments_db = TinyDB(comments_db_file)
    for filepath in glob.iglob(src_dir+"/*" , recursive=True):
        print(filepath) 
        if filepath.endswith(".c") or filepath.endswith(".h"):
            extract_comments(filepath,"OPENED COMMENT BEGIN","OPENED COMMENT END",comments_db)