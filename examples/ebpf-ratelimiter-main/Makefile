#ebpf3
BASEDIR=/root/github/
#ebpf1
#BASEDIR=/home/sayandes/
#CLANG=$(BASEDIR)/katran/_build//deps/clang/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04/bin/clang 
CLANG=clang
LLC=llc
#LLC=$(BASEDIR)/katran/_build//deps/clang/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04/bin/llc
INLCUDE_SYS=/usr/include
INCLUDE_LOC=/include
XDP_TARGETS := ratelimiting_kern 
#XDP_TARGETS := ratelimiting_kern-TC 
XDP_USER_TARGETS := ratelimiting_user

BPF_CFLAGS ?= -I$(INLCUDE_SYS) -I$(INCLUDE_LOC)

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
XDP_USER_C = ${XDP_USER_TARGETS:=.c}
XDP_USER_OBJ = ${XDP_USER_C:.c=.o}

$(info XDP_OBJ="$(XDP_OBJ)")
$(info XDP_C="$(XDP_C)")

all: $(XDP_OBJ) #$(XDP_USER_OBJ)

$(XDP_OBJ): %.o: %.c 
	$(CLANG)   $(BPF_CFLAGS) \
	-DDEBUG -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
	-O2 -emit-llvm -c -g -o  ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(XDP_USER_OBJ): %.o: %.c 
	$(CLANG)   $(BPF_CFLAGS) \
	-DDEBUG -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
	-O2 -emit-llvm -c -g -o  ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

