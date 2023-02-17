SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CFLAGS=-fno-stack-protector
# Replace this by the compiled kernel source folder
KERNEL_SOURCES=/root/ebpf_hhf_kernel/

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	clang-9 $(CFLAGS) -O1 -D__KERNEL__ -D__TARGET_ARCH_x86 -Wno-unused-value -Wno-compare-distinct-pointer-types -g \
		-I$(KERNEL_SOURCES)/include -I $(KERNEL_SOURCES)/arch/x86/include/ -I $(KERNEL_SOURCES)/tools/lib/bpf/ \
		-I$(KERNEL_SOURCES)/arch/x86/include/generated \
		-emit-llvm -c $< -o - | llc-9 -march=bpf -mattr=+alu32 -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o

