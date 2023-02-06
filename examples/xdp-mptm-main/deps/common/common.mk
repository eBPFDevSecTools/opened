
# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

CCFLAGS ?= -Wall -Werror
BPF_CCFLAGS ?= $(CCFLAGS) -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/
HEADERS_DIR ?= ../headers/
LIBBPF_DIR ?= ../libbpf/src/
BIN ?= ./build
SRC_DIR ?= src
USER_SRC_DIR ?= ${SRC_DIR}/user
KERNEL_SRC_DIR ?= ${SRC_DIR}/kernel

COPY_LOADER ?=
LOADER_DIR ?= $(COMMON_DIR)/../basic-solutions

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I${HEADERS_DIR}/ -I${DEPS}/
CFLAGS += -I$(SRC_DIR)/

LDFLAGS ?= -L$(LIBBPF_DIR)

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I${HEADERS_DIR}/ -I$(DEPS)/ -I$(SRC_DIR)/
LIBS = -l:libbpf.a -lelf -lz $(USER_LIBS)

ifeq ($(MPTM_DEBUG), y)
BPF_CFLAGS += -D__MPTM_DEBUG__
endif

all: llvm-check create-dirs $(USER_TARGETS) $(XDP_TARGETS) $(COPY_LOADER) $(COPY_STATS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER) $(COPY_STATS)
	rm -f *.ll
	rm -f *~
	rm -rf ${BIN}

ifdef COPY_LOADER
$(COPY_LOADER): $(LOADER_DIR)/${COPY_LOADER:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_LOADER)
	cp $(LOADER_DIR)/$(COPY_LOADER) $(COPY_LOADER)
endif

ifdef COPY_STATS
$(COPY_STATS): $(LOADER_DIR)/${COPY_STATS:=.c} $(COMMON_H)
	make -C $(LOADER_DIR) $(COPY_STATS)
	cp $(LOADER_DIR)/$(COPY_STATS) $(COPY_STATS)
# Needing xdp_stats imply depending on header files:
EXTRA_DEPS += $(COMMON_DIR)/xdp_stats_kern.h $(COMMON_DIR)/xdp_stats_kern_user.h
endif

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

create-dirs:
	mkdir -p ${BIN}

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
		mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=objs; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: ${USER_SRC_DIR}/%.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CC) $(CCFLAGS) $(CFLAGS) $(LDFLAGS) -o ${BIN}/$@ $(COMMON_OBJS) \
	 $< $(LIBS)

$(XDP_TARGETS): %.o: ${KERNEL_SRC_DIR}/%.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(OBJECT_LIBBPF)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
		$(BPF_CFLAGS) $(BPF_CCFLAGS) \
	    -O2 -emit-llvm -c -g -o ${BIN}/${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o ${BIN}/$@ ${BIN}/${@:.o=.ll}


