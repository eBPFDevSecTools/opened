FROM ubuntu:latest

#install dependencies for codequery
RUN apt-get update && apt-get upgrade && apt-get dist-upgrade && apt-get install -y \ 
	build-essential \
	g++ \
	git \
	cmake \
	ninja-build \
	sqlite3 \
	libsqlite3-dev \
	cscope \
	wget \
	python3 \
	python3-pip \
	exuberant-ctags \
	vim \
#add ebpf compilation tools
	clang \
	llvm \
	libelf-dev \
	libpcap-dev \
	gcc-multilib \
	build-essential \
	linux-tools-common \
	linux-tools-generic \
	tcpdump 

#install python dependencies
RUN python3 -m pip install command
RUN python3 -m pip install pytest-shutil
RUN python3 -m pip install argparse
RUN python3 -m pip install lxml

RUN mkdir /root/deps
RUN rm -rf /root/deps/codequery
RUN mkdir /root/deps/codequery
ADD codequery /root/deps/codequery
RUN rm -rf /root/deps/codequery/build
RUN mkdir /root/deps/codequery/build
WORKDIR /root/deps/codequery/build

#make codequery
RUN cmake -G Ninja -DNO_GUI=ON ..
RUN ninja 
RUN ninja install


#install txl
WORKDIR /root
RUN wget -O /tmp/txl.tgz  https://www.txl.ca/download/15372-txl10.8b.linux64.tar.gz
RUN tar -xvzf '/tmp/txl.tgz' --strip-components 1 --one-top-level=/root/deps/txl -C .
RUN ls /root
WORKDIR /root/deps/txl
RUN ./InstallTxl

#add extraction code 
WORKDIR /root
ADD asset asset
ADD extraction_runner.py extraction_runner.py
ADD function-extractor.py function-extractor.py
ADD run.sh run.sh
#RUN ./run.sh
