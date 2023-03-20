import re
import json
from tinydb import TinyDB
from datetime import date
import argparse
import glob
import os
from tinydb import Query
from tinydb.operations import set

def update_human_func_description(comments_db,comment_dict):
    funcName = comment_dict['funcName']
    #remove * from function name
    funcName = funcName.replace("*","")
    file_name = comment_dict['File']
    fname = file_name.split('/')[-1]
    startLine = comment_dict['startLine']
    human_comments = comment_dict['humanFuncDescription']
    json_str = json.dumps(human_comments)

    print("Human Comments JSON: "+json_str)
    q = Query()
    print("Checking funcName: "+funcName+" fname: "+fname+ " file_name: "+file_name)
    res = comments_db.search(q.funcName.search(funcName) & q.File.search(fname))
    #res = comments_db.search(q.funcName.search(funcName))
    print("Query Result1: " + str(len(res)))
    print(res)

    for e in res:
        print(e['funcName'])
        human_descs = e['humanFuncDescription']
        print("Human Descs: "+ str(len(human_descs)))
        print(human_descs)
        if(len(human_descs) == 1) :
            desc = human_descs[0]
            print("desc: ")
            print(desc)
            #if desc == None or desc == "{}":
            #Fix if for None
            #comments_db.update(set('humanFuncDescription',c),(Query().funcName.matches(funcName))  & (Query().File.search(fname)))
            for human_comment in human_comments:
                human_descs.append(human_comment)
            comments_db.update(set('humanFuncDescription',human_descs),(Query().funcName.matches(funcName))  & (Query().File.search(fname))  )

            print("UPDATED")
            print("UPDATED HUMAN DESCS:")
            print(human_descs)

        else:
            #check if description is empty
            #human_descs.append(json_str)
            for human_comment in human_comments:
                human_descs.append(human_comment)
            comments_db.update(set('humanFuncDescription',human_descs),(Query().funcName.matches(funcName))  & (Query().File.search(fname))  )
            print("UPDATED")
            print("UPDATED HUMAN DESCS:")
            print(human_descs)

            
    print("VALIDATING")
    res = comments_db.search(q.funcName.search(funcName) & q.File.search(fname) )
    #res = comments_db.search(q.funcName.search(funcName))
    print("Query REsult2: " + str(len(res)))
    print(res)
    for e in res:
        print(e['funcName'])
        print(e['humanFuncDescription'])


     


def get_human_func_description(human_comments_file, path, func_name):
    cdict = {}
    if human_comments_file == None:
        return cdict
    db = TinyDB(human_comments_file)
    fname = path.split('/')[-1]
    q = Query()
    res = db.search(q.Funcname.search(func_name) & q.File.search(fname))
    #print("Result")
    #print(res)
    if len(res) > 1:
        print("WARNING: MULTIPLE FILES MATCHING FNAME")
    
    for e in res:
        cdict['description'] = e['Func_Description']
        cdict['author'] = e['author']
        cdict['authorEmail'] = e['email']
        cdict['date'] = e['date']
        return cdict

def get_func_description(db, path, op_dict):
    fname = path.split('/')[-1]
    q = Query()
    res = comments_db.search(q.File.search(fname))
    #print("Result")
    #print(res)
    cdict = {}
    for e in res:
        print(e['email'])
        print(e['File'])
        print(e['Helpers'])
        print(e['Func_Description'])

def check_if_file_already_exists(files):
    for fl in files:
        print("Checking: ",fl)
        if os.path.exists(fl) is True :
            print("File: ",fl," already exists.. ", "Exiting")
            return True
    return False

def check_if_file_does_not_exist(files):
    for fl in files:
        print("Checking: ",fl)
        if os.path.exists(fl) is False:
            print("File: ",fl," does not exist.. ", "Exiting")
            return True
    return False

def insert_to_db(db,comment_dict):
    comment_json = json.dumps(comment_dict)
    #print("Inserting comments to DB: "+ comment_json )
    db.insert(comment_dict)

def get_author(author_dict, file_name, op_dict):
    for element in author_dict:
        author_file_path = element['file']
        author_file_name = author_file_path.split('/')[-1]
        print(author_file_name)
        if file_name in author_file_name:
            op_dict[AUTHOR] = element[AUTHOR_NAME]
            op_dict[EMAIL] = element[AUTHOR_EMAIL]
            return op_dict
    return op_dict

def extract_comments(file_name,start_pattern,end_pattern,db):
    comments_list = []
    print("PROCESSING: "+file_name)
    src_file = open(file_name,'r')
    data = src_file.read()
    #print(data)
    #TODO: Try a regular expression insted of multiple split operations
    tokens = data.split(start_pattern)
    #print("TOKENS")
    #print(tokens)
    for token in tokens[1:]:
        #print("TOKEN")
        #print(token)
        comment = token.split(end_pattern)[0]
        print("COMMENT")
        print(comment)

        op_dict = {}
        op_dict['date']= str(date.today())
        lines = comment.split('\n')
        #print(lines)
        ct = 1
        done = False
        for ct in range(1,len(lines)):
            if done == True:
                break;
            line = lines[ct]
            # ALready processed this line as part of function description
            if ct >= len(lines):
                break
            line_tokens = line.split(':')
            if len(line_tokens) < 2:
                continue
            #print("line_tokens")
            #print(line_tokens)
            key = line_tokens[0]
            key = key.strip()
            key = re.sub(r'\s+', '_', key)
            print("Key: "+key+" ct: "+str(ct))
            value = ""
            # text itself may contain ":"
            for text in line_tokens[1:]:
                value = value + text
            if key == "Func_Description":
                print("Func_Desc: "+str(ct))
                #ct = ct + 2 # why 2? Seems to work
                ct = ct + 1 
                while ct < len(lines):
                    print("ct: "+str(ct))
                    value = value + lines[ct]
                    ct = ct + 1
                done = True
                print("Func_Description_val: "+value)
            op_dict[key] = value
            ct = ct + 1
        print(op_dict)
        #print(json.dumps(op_dict))
        
        comments_list.append(op_dict)
    return comments_list

def extract_comments_from_json(file_name,start_pattern,end_pattern,db):
    comments_list = []
    print("PROCESSING: "+file_name)
    src_file = open(file_name,'r')
    data = src_file.read()
    #print(data)
    #TODO: Try a regular expression insted of multiple split operations
    tokens = data.split(start_pattern)
    #print("TOKENS")
    #print(tokens)
    for token in tokens[1:]:
        #print("TOKEN")
        #print(token)
        comment = token.split(end_pattern)[0]
        print("COMMENT")
        print(comment)
        op_dict = json.loads(comment,strict=False)
        print(op_dict)
        comments_list.append(op_dict)
    return comments_list

        
    

if __name__ == "__main__":
    
    AUTHOR = 'author'
    AUTHOR_NAME = 'authorName'
    AUTHOR_EMAIL = 'authorEmail'
    FILE = 'file'
    EMAIL = 'email'

    my_parser = argparse.ArgumentParser()
    my_parser.add_argument('-s','--src_dir',action='store',required=True,
            help='directory with source code')
    my_parser.add_argument('-d','--comments_dbfile',action='store',required=True,
            help='comments db file')
    my_parser.add_argument('-a','--authors_file',action='store',required=False,
            help='file to authors mapping json file')
    args = my_parser.parse_args()

    #authors_file = "./op/code_annotation_bu/boston_files_to_authors.json"
    
    src_dir = args.src_dir
    comments_db_file=args.comments_dbfile
    authors_file = args.authors_file

    files = []
    files.append(src_dir)
    files.append(comments_db_file)
    if authors_file != None:
        files.append(authors_file)

    if check_if_file_does_not_exist(files)  == True:
        print("Input file does not Exist..Quitting")
        exit(0)
    '''
    files.clear()
    files.append(comments_db_file)
    if check_if_file_already_exists(files)  == True:
        print("Comments db file already exists..Quitting")
        exit(0)

    '''
    
    #comments_db_file="boston_comments.json"
    comments_db = TinyDB(comments_db_file)
    for filepath in glob.iglob(src_dir+"/*" , recursive=True):
        fname = filepath.split('/')[-1]
        print("path: "+filepath+" name: "+fname) 
        if filepath.endswith(".c") or filepath.endswith(".h"):
            if authors_file != None:
                    comments_list= extract_comments(filepath," OPENED COMMENT BEGIN","OPENED COMMENT END",comments_db)
            else:
                    comments_list= extract_comments_from_json(filepath," OPENED COMMENT BEGIN","OPENED COMMENT END",comments_db)

            for op_dict in comments_list:
                if authors_file != None:
                    with open (authors_file) as json_str:
                        author_dict = json.load(json_str)
                        op_dict = get_author(author_dict, fname, op_dict)
                print(op_dict)
                update_human_func_description(comments_db,op_dict)
