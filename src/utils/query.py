import json
from tinydb import TinyDB
from tinydb import Query

if __name__ == "__main__":
    comments_db_file = "/home/palani/github/opened_extraction/op/katran/commented_katran/katran_comments.db"
    comments_db = TinyDB(comments_db_file)
    '''
    q = Query()
    res = comments_db.search(q)
    print("Result")
    print(res)
    if len(res) > 1:
        print("WARNING: MULTIPLE FILES MATCHING FNAME")
   ''' 
    for e in comments_db.all():
        print(e)
        for desc in e['humanFuncDescription']:
            txt = desc['description'] 
            if txt != '':
                print(e['File'])
                print(e['funcName'])
                print(e['startLine'])
                print(e['endLine'])
                print(txt)
                print("-----------------")
