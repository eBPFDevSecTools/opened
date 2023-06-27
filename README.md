# OPENED Extraction Tool

LPC 2022 blurb describing the goal of the tool and an initial prototype is here: https://lpc.events/event/16/contributions/1370/ 
 
## Dependencies
 1. Works on a) kernel verion 5.4.0-131, Ubuntu 22:04, Intel arch x86 arch b) Dockerfile works with Wondows 10, WSL2+Docker Desktop with Ubuntu 22.04 App from MS store. There is a known issue with Apple Silicon based Macbooks with installing a) ``gcc-multlib`` b) TXL and c) Codequery, described [here](https://github.com/eBPFDevSecTools/opened/issues/37)
 2. git
 3. Docker
 
## Download
 1. Run ``git clone git@github.com:eBPFDevSecTools/opened.git`` followed by ``git submodule update --init --recursive``
 2. ``cd opened``
 3. To update the submodules a) ``git submodule update --remote --merge`` b) ``cd codequery; git pull``
 
## Install 
### Process 1: Docker
 1. ``mkdir op`` To store the output of extraction phase (or any other folder name)
 2. ``docker build . -t opened/extract:0.01``

### Process 2: On Host
 1. **For now:** You will need to parse the Dockerfile and execute the installation steps on your host system.
 2. In future we will provide a script for on-host installation ([Issue #24](https://github.com/eBPFDevSecTools/opened/issues/24)).
 
## Updating local branch
 1. run ``git pull``
 2. run ``git submodule update --recursive`` 
 3. If you have docker for install, you are done. 
 4. If you have on-host install, you will need to re-install ``codequery`` by running the relevant instructions from Dockerfile.

## Extraction code and artefacts
Code extraction consists of three phases 1) Determining the necessary functions and data-structures to be copied, 2) (Manual) disambiguation of the target set of functions identified in previous step and 3) Extracting required code from source files to generate an independantly compilable module.


### Phase I: Determining necessary functions and data-structures for extracting specific functionality
1. Run annotated function call graph extraction phase, 
```
python3 src/extraction_runner.py --help
usage: extraction_runner.py [-h] -s SRC_DIR -f FUNCTION_NAME [-d DB_FILE_NAME] [-g FUNCTION_CALL_GRAPH_PATH] -r REPO_NAME

optional arguments:
  -h, --help            show this help message and exit
  -s SRC_DIR, --src_dir SRC_DIR
                        directory with source code
  -f FUNCTION_NAME, --function_name FUNCTION_NAME
                        function name to be extracted
  -d DB_FILE_NAME, --db_file_name DB_FILE_NAME
                        Optional sqlite3 database with cqmakedb info
  -g FUNCTION_CALL_GRAPH_PATH, --function_call_graph_path FUNCTION_CALL_GRAPH_PATH
                        directory to put function and map dependency call graph file. Output of phase I
  -r REPO_NAME, --repo_name REPO_NAME
                        Project repository name

```
NOTE:  **example is given in run2.sh**.

### Phase II
1. Open the func.out file and remove the duplicate function and struct definitions.  This will output an annotated function call graph in a file named func.out. Note that func.out may have duplicate function defintions. We expect the developer to disambiguate and identify the required set of functions to be extracted in Phase II.

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
Note that  STRUCT_INFO and FUNC_INFO are generated using the [annotator](https://github.com/eBPFDevSecTools/ebpf-projects-annotations/blob/master/ANNOTATION_GENERATOR.md) script in the [eBPF-projects-annotations repo](https://github.com/eBPFDevSecTools/ebpf-projects-annotations) 

Note that extracted.c may contain duplicate eBPF Map defintions within and ```ATTENTION``` section. We expect the developer to choose the right map definition and delete the offending defintion.


*Compilation*

Run `make` to compile the extracted code.
