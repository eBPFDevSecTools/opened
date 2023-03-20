#bcc
python3 src/utils/comment_extractor.py -s ./op/bcc/commented_bcc -d ./op/bcc/commented_bcc/bcc_comments_human.db

#mptm
python3 src/utils/comment_extractor.py -s  /home/palani/github/opened_extraction/human_annotations/human_commented_xdp-mptm-main/ -d /home/palani/github/opened_extraction/op/xdp-mptm-main/commented_xdp-mptm-main/xdp-mptm-main.db_comments.db

#rate-limiter
python3 src/utils/comment_extractor.py -s  /home/palani/github/opened_extraction/human_annotations/human_commented_ebpf-ratelimiter-main -d /home/palani/github/opened_extraction/op/ebpf-ratelimiter-main/commented_ebpf-ratelimiter-main/ebpf-ratelimiter-main.db_comments.db

#bpf-filter
python3 src/utils/comment_extractor.py -s /home/palani/github/opened_extraction/human_annotations/human_commented_bpf-filter-master/ -d  /home/palani/github/opened_extraction/op/bpf-filter-master/commented_bpf-filter-master/bpf-filter-master.db_comments.db
