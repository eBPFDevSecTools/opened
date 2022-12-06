#python3 extraction_runner.py -f xdpdecap -o txl -s examples/katran
#python3 extraction_runner.py -f from_overlay -o txl_cilium -s examples/cilium
python3 extraction_runner.py -f sock4_connect -o txl_cilium -s examples/cilium
#python3 extraction_runner.py -f handle_ipv6 -o txl_cilium -s examples/cilium
#python3 extraction_runner.py -f tail_handle_ipv6 -o txl_cilium -s examples/cilium
#python3 extraction_runner.py -f handle_ipv4 -o txl_cilium -s examples/cilium
#python3 extraction_runner.py -f tail_handle_ipv4 -o txl_cilium -s examples/cilium
