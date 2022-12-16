
BASEDIR=/root/github/
ROOT_DIR=.
# Mimics the mcpu values set by cilium-agent. See GetBPFCPU().
ifeq ("$(KERNEL)","49")
LLC_FLAGS += -mcpu=v1
else ifeq ("$(KERNEL)","netnext")
LLC_FLAGS += -mcpu=v3
else
LLC_FLAGS += -mcpu=v2
endif


FLAGS :=  -I$(ROOT_DIR) -D__NR_CPUS__=$(shell nproc --all) -O2 -g
LIB := $(shell find $(ROOT_DIR) -name '*.h') $(BUILD_PERMUTATIONS_DEP)
BPF_C := $(patsubst %.o,%.c,$(BPF))
BPF_ASM := $(patsubst %.o,%.s,$(BPF))


#ebpf3
#ebpf1
#BASEDIR=/home/sayandes/
CLANG=clang
LLC=llc
INCLUDE_LOCAL=$(ROOT_DIR)/include
INCLUDE_LOCAL_LIB=$(ROOT_DIR)/lib
INLCUDE_SYS=/usr/include
INCLUDE_LOC=/include
XDP_TARGETS=extracted
BPF_CFLAGS ?= -I$(INLCUDE_SYS) -I$(INCLUDE_LOC) -I$(INCLUDE_LOCAL) -I$(INCLUDE_LOCAL_LIB)

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

$(XDP_OBJ): %.o: %.c 
	$(CLANG) $(FLAGS)  $(BPF_CFLAGS) \
	-DSKIP_DEBUG -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
	-O2 -emit-llvm -c -g -o  ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
clean:
	rm *.o *.ll
