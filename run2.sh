
#python3 extraction_runner.py -f bpf_sockmap -o txl_cilium -s examples/cilium -g fcg

#python3 extraction_runner.py -f tail_handle_ipv6 -o txl_cilium -s examples/cilium

#python3 extraction_runner.py -f tail_handle_ipv4 -o txl_cilium -s examples/cilium

# works 

#python3 extraction_runner.py -f xdpdecap -o txl_katran -s examples/katran -g fcg
#python3 src/extraction_runner.py -f xdpdecap -d katran.db -g op/fcg  -r katran
#python3 src/extraction_runner.py -f handle_ipv4 -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f sock4_connect -d cilium.db -g op/fcg  -r cilium 

#not works

#python3 extraction_runner.py -f handle_ipv6 -o txl_cilium -s examples/cilium
# got this error: error: ./lib/maps.h:279:2: in function tail_icmp6_handle_ns i32 (%struct.__sk_buff*): A call to built-in function 'abort' is not supported.
#python3 extraction_runner.py -f from_overlay -o txl_cilium -s examples/cilium
# got this error: error: ./lib/maps.h:279:2: in function tail_icmp6_handle_ns i32 (%struct.__sk_buff*): A call to built-in function 'abort' is not supported.

#python3 extraction_runner.py -f sock4_connect -o txl_cilium -s examples/cilium -g fcg -c commented_cilium -r asset/helper_hookpoint_map.json


#works
#python3 extraction_runner.py -f xdpdecap -d katran.db -g fcg -t op/katran.function_list.json -s op/katran.struct_list.json -r katran
