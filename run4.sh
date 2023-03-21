#bcc
python3 src/utils/comment_extractor.py -s  /home/palani/github/opened_extraction/human_annotations/human_commented_bcc/ -d /home/palani/github/opened_extraction/op/bcc/commented_bcc/bcc.db_comments.db

cp /home/palani/github/opened_extraction/op/bcc/commented_bcc/bcc.db_comments.db ./repo_db/bcc_annotated.db

#mptm
python3 src/utils/comment_extractor.py -s  /home/palani/github/opened_extraction/human_annotations/human_commented_xdp-mptm-main/ -d /home/palani/github/opened_extraction/op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db

cp /home/palani/github/opened_extraction/op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db xdp-mptm-main_annotated.db

#rate-limiter
python3 src/utils/comment_extractor.py -s  /home/palani/github/opened_extraction/human_annotations/human_commented_ebpf-ratelimiter-main -d /home/palani/github/opened_extraction/op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db

cp /home/palani/github/opened_extraction/op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db ebpf-ratelimiter-main_annotated.db

#bpf-filter
python3 src/utils/comment_extractor.py -s /home/palani/github/opened_extraction/human_annotations/human_commented_bpf-filter-master/ -d  /home/palani/github/opened_extraction/op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db

cp /home/palani/github/opened_extraction/op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db bpf-filter-master_annotated.db


