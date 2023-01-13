/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_ACCESS_H_
#define __BPF_ACCESS_H_

#include "compiler.h"

#if !defined(__non_bpf_context) && defined(__bpf__)
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/bpf/access.h,
 Startline: 10,
 Endline: 33,
 Funcname: map_array_get_32,
 Input: (const __u32 *array, __u32 index, const __u32 limit),
 Output: static__always_inline__maybe_unused__u32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __always_inline __maybe_unused __u32
map_array_get_32(const __u32 *array, __u32 index, const __u32 limit)
{
	__u32 datum = 0;

	if (__builtin_constant_p(index) ||
	    !__builtin_constant_p(limit))
		__throw_build_bug();

	/* LLVM tends to optimize code away that is needed for the verifier to
	 * understand dynamic map access. Input constraint is that index < limit
	 * for this util function, so we never fail here, and returned datum is
	 * always valid.
	 */
	asm volatile("%[index] <<= 2\n\t"
		     "if %[index] > %[limit] goto +1\n\t"
		     "%[array] += %[index]\n\t"
		     "%[datum] = *(u32 *)(%[array] + 0)\n\t"
		     : [datum]"=r"(datum)
		     : [limit]"i"(limit), [array]"r"(array), [index]"r"(index)
		     : /* no clobbers */ );

	return datum;
}
#else
# define map_array_get_32(array, index, limit)	__throw_build_bug()
#endif /* !__non_bpf_context && __bpf__ */
#endif /* __BPF_ACCESS_H_ */
