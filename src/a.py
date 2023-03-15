
#1. make q of nodes which dont call any function
#2. make a map<key=node,value=all nodes calling this function>1
#3. make a map<key=node,value=all nodes called by this function>2
def add_level_info(helperdict):
    q = []
    level_dict = dict()
    for fn in helperdict.keys():
        for en in helperdict[fn]:
            key = fn #+':'+en['startLine']+':'+en['File']
            if en['call_depth'] == 0:
                q.append(key)
                level_dict[key] = 0
            else:
                map2[key] = len(en['called_function_list'])
                for f in en['called_function_list']:
                    if f not in map1:
                        map1[f] = list()
                    map1[f].append(fn)
    level = 0
    while len(q) != 0:
        n = len(q)
        for idx in range(n):
            nd = q.pop(0)
            level_dict[nd] = level
            for en in map1[nd]:
                map2[en] = map2[en] - 1
                if map2[en] == 0:
                    q.append(en)
            level = level + 1
    print(level_dict)

