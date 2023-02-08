python3 src/annotator.py -o op/katran/txl_katran -s examples/katran -c op/katran/commented_katran -t op/katran/katran.function_file_list.json -u op/katran/katran.struct_file_list.json -d op/code_annotation_bu/Katran/boston_katran_comments.json 
python3 src/annotator.py -o op/cilium/txl_cilium -s examples/cilium -c op/cilium/commented_cilium -t op/cilium/cilium.function_file_list.json -u op/cilium/cilium.struct_file_list.json --isCilium -d op/code_annotation_bu/Cilium/boston_cilium_comments.json

#python3 src/annotator.py -o op/bcc/txl_bcc -s examples/bcc -c op/bcc/commented_bcc -t op/bcc/bcc.function_file_list.json -u op/bcc/bcc.struct_file_list.json 

#python3 src/annotator.py -o op/vpf-ebpf-src/txl_vpf-ebpf-src -s examples/vpf-ebpf-src -c op/vpf-ebpf-src/commented_vpf-ebpf-src -t op/vpf-ebpf-src/vpf-ebpf-src.function_file_list.json -u op/vpf-ebpf-src/vpf-ebpf-src.struct_file_list.json
