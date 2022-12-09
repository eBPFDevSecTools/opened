python3 function-extractor.py -o op/katran -e extracted.c -c fcg/katran.xdpdecap.cg.out -t txl_katran -s examples/katran -b /home/sayandes/opened_extraction/examples/katran

#python3 function-extractor.py -o op/katran -e extracted.c -c func.out -t txl -s examples/katran
#python3 function-extractor.py -o op/cilium -e extracted.c -c func.out -t txl_cilium -s examples/cilium
#python3 function-extractor.py -o op/cilium -e extracted.c -c tail_handle_ipv4.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium



#works
#python3 function-extractor.py -o op/cilium -e extracted.c -c cilium.sock4_connect.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium
#python3 function-extractor.py -o op/cilium -e extracted.c -c fcg/cilium.handle_ipv4.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium

#not works
#python3 function-extractor.py -o op/cilium -e extracted.c -c cilium.handle_ipv6.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium
#python3 function-extractor.py -o op/cilium -e extracted.c -c cilium.from_overlay.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium

#TO make it work, 1) need to move extracted.c and Makefile to sockops folder 2) Do #defines before includes
#python3 function-extractor.py -o op/cilium -e extracted.c -c fcg/cilium.sock4_connect.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium
