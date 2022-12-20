# OPENED Exraction Tool

LPC 2022 blurb describing the goal of the tool and an initial prototype is here: https://lpc.events/event/16/contributions/1370/ 
 
## Dependencies
 1. Works on a) kernel verion 5.4.0-131, Ubuntu 22:04, Intel arch x86 arch b) Dockerfile works with Wondows 10, WSL2+Docker Desktop with Ubuntu 22.04 App from MS store. There is a known issue with Apple Silicon based Macbooks with installing a) ``gcc-multlib`` b) TXL and c) Codequery, described [here](https://github.com/sdsen/opened_extraction/issues/37)
 2. git
 3. Docker
 
## Download
 1. ``git clone --recurse-submodules git@github.com:sdsen/opened_extraction.git``
 2. ``cd opened_extraction``
 3. 
 4. To update the submodules a) ``git submodule update --remote --merge`` b) ``cd codequery; git pull``
 
## Install 
### Process 1: Docker
 1. ``mkdir op`` To store the output of extraction phase (or any other folder name)
 2.  ``docker build . -t opened/extract:0.01``

### Process 2: on host
 1. **For now:** You will need to parse the Dockerfile and execute the installation steps on your host system.
 2. In future we will provide a script for on-host installation ([Issue #24](https://github.com/sdsen/opened_extraction/issues/24)).
 
## Updating local branch
 1. run ``git pull``
 2. run ``git submodule update --recursive`` 
 3. If you have docker for install, you are done. 
 4. If you have on-host install, you will need to re-install ``codequery`` by running the relevant instructions from Dockerfile.

## Extraction code and artefacts

Code extraction consists of two phases 1) Generating annotated function call graph 2) Extracting required code from source files to generate an independantly compilable module.


### Phase I: Annotated Function Call Generation

 1. Run the docker. ``docker run -it --privileged --mount type=bind,src=<source_code_dir_on_host>/opened_extraction/examples,dst=/root/examples --mount type=bind,src=<source_code_dir_on_host>/opened_extraction/op, dst=/root/op opened/extract:0.01``. Where ``op`` is the folder created in step Install.3 . The output is expected to be dumped in this folder, so that it is available for later processing/use in host system.

2. Run annotator phase1, 
```
python3 src/annotator.py
usage: annotator.py [-h] [-annotate_only ANNOTATE_ONLY] -s SRC_DIR -o TXL_OP_DIR [-c OPENED_COMMENT_STUB_FOLDER] [-r BPFHELPERFILE]
                    [-t TXL_FUNCTION_LIST] [-u TXL_STRUCT_LIST] [--isCilium]

optional arguments:
  -h, --help            show this help message and exit
  -annotate_only ANNOTATE_ONLY
  -s SRC_DIR, --src_dir SRC_DIR
                        directory with source code
  -o TXL_OP_DIR, --txl_op_dir TXL_OP_DIR
                        directory to put txl annotated files
  -c OPENED_COMMENT_STUB_FOLDER, --opened_comment_stub_folder OPENED_COMMENT_STUB_FOLDER
                        directory to put source files with comment stub
  -r BPFHELPERFILE, --bpfHelperFile BPFHELPERFILE
                        Information regarding bpf_helper_funcitons
  -t TXL_FUNCTION_LIST, --txl_function_list TXL_FUNCTION_LIST
                        JSON with information regarding functions present. output of foundation_maker.py
  -u TXL_STRUCT_LIST, --txl_struct_list TXL_STRUCT_LIST
                        JSON with information regarding structures present. output of foundation_maker.py
  --isCilium            whether repository is cilium

```
NOTE: **example is given in run1.sh**
 
3. Run annotated function call graph extraction phase, 
```
python3 src/extraction_runner.py -h
usage: extraction_runner.py [-h] [-annotate_only ANNOTATE_ONLY] -f FUNCTION_NAME -d DB_FILE_NAME [-g FUNCTION_CALL_GRAPH_PATH] [-r REPO_NAME]

optional arguments:
  -h, --help            show this help message and exit
  -annotate_only ANNOTATE_ONLY
  -f FUNCTION_NAME, --function_name FUNCTION_NAME
                        function name to be extracted
  -d DB_FILE_NAME, --db_file_name DB_FILE_NAME
                        sqlite3 database with cqmakedb info
  -g FUNCTION_CALL_GRAPH_PATH, --function_call_graph_path FUNCTION_CALL_GRAPH_PATH
                        directory to put function and map dependency call graph file. Output of phase I
  -r REPO_NAME, --repo_name REPO_NAME
                        Project repository name

```
NOTE:  **example is given in run2.sh**.
### Phase II
1. Open the func.out file and remove the duplicate function and struct definitions. A cleaned **func.out.cleaned is shown in asset folder**. This will output an annotated function call graph in a file named func.out. Note that func.out may have duplicate function defintions. We expect the developer to disambiguate and identify the required set of functions to be extracted in Phase II.

### Phase III: Extracting Required Code
2. Run the function extractor to extract and dump required functions and map definitions.

```
python3 src/function-extractor.py -h
usage: function-extractor.py [-h] -o OPDIR -c CODEQUERYOUTPUTFILE -e EXTRACTEDFILENAME -t STRUCT_INFO -f FUNC_INFO -s SRCDIR -b BASEDIR [--isCilium]

Function Extractor

optional arguments:
  -h, --help            show this help message and exit
  -o OPDIR, --opdir OPDIR
                        directory to dump extracted files to
  -c CODEQUERYOUTPUTFILE, --codequeryOutputFile CODEQUERYOUTPUTFILE
                        Function and Map dependency output from codequery
  -e EXTRACTEDFILENAME, --extractedFileName EXTRACTEDFILENAME
                        Output file with extracted function
  -t STRUCT_INFO, --struct_info STRUCT_INFO
                        json file containing struct definitions in the repo
  -f FUNC_INFO, --func_info FUNC_INFO
                        json file containing function definitions in the repo
  -s SRCDIR, --srcdir SRCDIR
                        Directory containing source files for function to be extraced from
  -b BASEDIR, --basedir BASEDIR
                        Base Directory path relative to which directory structure in opdir will be created
  --isCilium            whether repository is cilium
```
Note that extracted.c may contain duplicate eBPF Map defintions within and ```ATTENTION``` section. We expect the developer to choose the right map definition and delete the offending defintion.


*Compilation*

Run `make` to compile the extracted code.
