
/* SPDX-License-Identifier: GPL-2.0-or-later
 * 
 *  Code taken from https://github.com/CentaurusInfra/mizar
 *  @file transit_kern.h
 *  @author Sherif Abdelwahab (@zasherif)
 *  @copyright Copyright (c) 2019 The Above Author(s) of Mizar.
 * 
 * Adapted by:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#ifndef __KERNEL_LIB_GENEVE_H__
#define __KERNEL_LIB_GENEVE_H__

#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Actual geneve header used in packet */

struct geneve_opt {
    __be16 opt_class;
    __u8 type;
    __u8 length : 5;
    __u8 r3 : 1;
    __u8 r2 : 1;
    __u8 r1 : 1;
    __u8 opt_data[];
};

struct genevehdr {
    /* Big endian! */
    __u8 opt_len : 6;
    __u8 ver : 2;
    __u8 rsvd1 : 6;
    __u8 critical : 1;
    __u8 oam : 1;
    __be16 proto_type;
    __u8 vni[3];
    __u8 rsvd2;
    //struct geneve_opt options[];
};

struct ipv4_tuple_t {
    __u32 saddr;
    __u32 daddr;

    /* ports */
    __u16 sport;
    __u16 dport;

    /* Addresses */
    __u8 protocol;

    /*TODO: include TCP flags, no use case for the moment! */
} __attribute__((packed));

#endif /* __KERNEL_LIB_GENEVE_H__ */
