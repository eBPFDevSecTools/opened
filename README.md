Install
docker build . -t opened/extract:0.01

Run:
Phase I:
1. docker run -it  --mount type=bind,src=/home/sayandes/extraction/katran,dst=/root/katran opened/extract:0.01
2. python3 extraction_runner.py -f <function_name> -s <source_folder> -o <txl_output>

Phase II:
1. Open the func.out file and remove the duplicate function definitions

Phase III:
2. python3 function-extractor.py -o/--opdir, -f/--codequeryOutputFile, -e/--extractedFileName, -c/--cscopeFile, -t/--txlDir, -s/--srcdir  
