# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#  
# Authors:
# Dushyant Behl <dushyantbehl@in.ibm.com>
# Sayandeep Sen <sayandes@in.ibm.com>
# Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
#
# Currently we use the make framework of xdp-tutorials/common 
DEPS	     := ./deps

export MPTM_DEBUG   := n

SRC_DIR ?= src
USER_SRC_DIR ?= ${SRC_DIR}/user
KERNEL_SRC_DIR ?= ${SRC_DIR}/kernel

XDP_PROGS    := mptm mptm_extras
USER_TARGETS := mptm_user mptm_extras_user

XDP_TARGETS  := ${XDP_PROGS:=.o}
USER_LIBS    := -lbpf -lm

$(info XDP_TARGETS is [${XDP_TARGETS}])
$(info USER_TARGETS is [${USER_TARGETS}])
$(info MPTM_DEBUG is [${MPTM_DEBUG}])

LIBBPF_DIR  = ${DEPS}/libbpf/src
COMMON_DIR  = ${DEPS}/common
HEADERS_DIR = ${DEPS}/headers

EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk

.PHONY: tags
tags:
	ctags -e -R
