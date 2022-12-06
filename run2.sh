#python3 function-extractor.py -o op/katran -e extracted.c -c asset/func.out.cleaned -t txl -s examples/katran
#python3 function-extractor.py -o op/katran -e extracted.c -c func.out -t txl -s examples/katran
#python3 function-extractor.py -o op/cilium -e extracted.c -c func.out -t txl_cilium -s examples/cilium
#python3 function-extractor.py -o op/cilium -e extracted.c -c tail_handle_ipv4.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium
python3 function-extractor.py -o op/cilium -e extracted.c -c sock4_connect.cg.out -t txl_cilium -s examples/cilium -b /home/sayandes/opened_extraction/examples/cilium
