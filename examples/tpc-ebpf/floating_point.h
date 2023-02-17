#ifndef FLOATING_POINT_H
#define FLOATING_POINT_H

#include <linux/swab.h>
#include "bpf_helpers.h"
#include <uapi/linux/bpf.h>


#define BIAS 1024 /* == 2**10 - Above means positive exponent and below means negative one */
#define LARGEST_BIT ((__u64) 1U) << 63U
#define set_floating(dest, src) dest.mantissa = src.mantissa; \
								dest.exponent = src.exponent;
#define ONE(x) bpf_to_floating(1, 0, 1, &x, sizeof(floating))

// Float max decimal precision when transforming to u32s
#define FLOAT_MULT 1000000000UL

#endif