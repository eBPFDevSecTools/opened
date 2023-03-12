python3 src/utils/comment_extractor.py -s ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ -d ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.json
python3 src/utils/query.py -f /home/palani/func_level_info/ebpf-ratelimiter-main.function_file_list.json -d ./op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.json

python3 src/utils/comment_extractor.py -s ./op/bcc/commented_bcc -d ./op/bcc/commented_bcc/bcc_comments_human.db

python3 src/utils/query.py -f /home/palani/func_level_info/bcc.function_file_list.json  -d ./op/bcc/commented_bcc/bcc_comments_human.db

#mptm
python3 src/utils/comment_extractor.py -s ./op/xdp-mptm-main/commented_xdp-mptm-main -d ../../repo_db/mptm_comments.db
