# Builds an XDP program with dependent libraries and tools

LLC ?= llc
LLVM_STRIP ?= llvm-strip
CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

OUTPUT ?= $(CURDIR)/.output
LIBBPF_SRC ?= $(abspath ../libbpf/src)
LIBBPF_OBJECT ?= $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_SRC := $(abspath ../bpftool/src)
BPFTOOL ?= $(abspath $(OUTPUT)/bpftool/bpftool)
IPROUTE2_SRC := $(abspath ../iproute2)
IPROUTE2_TC ?= $(abspath $(OUTPUT)/iproute2/tc)

CFLAGS ?= -I$(OUTPUT) -I$(IPROUTE2_SRC)/include
LDFLAGS ?= -L$(OUTPUT)

LIBS = -l:libbpf.a -lelf -lz

# Build targets:
all: $(OUTPUT)/sockops.o $(OUTPUT)/sockmap_redir.o

$(OUTPUT) $(OUTPUT)/libbpf $(dir $(BPFTOOL)) $(dir $(IPROUTE2_TC)):
	mkdir -p $@

$(BPFTOOL): $(wildcard $(BPFTOOL_SRC)/*.[ch] $(BPFTOOL_SRC)/Makefile) | $(dir $(BPFTOOL))
	$(MAKE) OUTPUT=$(dir $(BPFTOOL)) -C $(BPFTOOL_SRC)

$(LIBBPF_OBJECT): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
	OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
	INCLUDEDIR= LIBDIR= UAPIDIR= install

$(IPROUTE2_TC): $(wildcard $(IPROUTE2_SRC/*/*[ch]) (LIBBPF_SRC)/Makefile) | $(dir $(IPROUTE2_TC))
	(cd $(IPROUTE2_SRC); pwd; ls -al; ./configure; git apply ../misc/iproute2.diff; make)
	mv $(IPROUTE2_SRC)/tc/tc $@

$(OUTPUT)/sockops.o: sockops.c sockops.h $(LIBBPF_OBJECT) | $(OUTPUT)
	$(CLANG) \
	    -g -O2 \
	    -target bpf \
	    -D__TARGET_ARCH_$(ARCH) \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUTPUT)/sockmap_redir.o: sockmap_redir.c sockops.h $(LIBBPF_OBJECT) | $(OUTPUT)
	$(CLANG) \
	    -g -O2 \
	    -target bpf \
	    -D__TARGET_ARCH_$(ARCH) \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -rf $(OUTPUT)
