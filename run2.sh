#python3 function-extractor.py -o op/katran -e extracted.c -c asset/func.out.cleaned -t txl -s examples/katran
#python3 function-extractor.py -o op/katran -e extracted.c -c func.out -t txl -s examples/katran
python3 function-extractor.py -o op/cilium -e extracted.c -c func.out -t txl_cilium -s examples/cilium
