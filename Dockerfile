#Author: Sayandeep Sen (sayandes@in.ibm.com)
#Author: Palani Kodeswaran (palani.kodeswaran@in.ibm.com)

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

#add verification tools
RUN apt-get install -y iproute2
RUN apt-get install -y net-tools


#install python dependencies
RUN python3 -m pip install command
RUN python3 -m pip install pytest-shutil
RUN python3 -m pip install argparse
RUN python3 -m pip install lxml
RUN python3 -m pip install tinydb

#install txl
WORKDIR /root
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

#add extraction code 
WORKDIR /root
ADD src src
ADD run2.sh run2.sh
ADD run3.sh run3.sh
#ADD op op
#ADD examples examples
#RUN ./run.sh
