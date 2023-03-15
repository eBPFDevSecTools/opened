/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/*
 * Note that bpf programs need to include either
 * vmlinux.h (auto-generated from BTF) or linux/types.h
 * in advance since bpf_helper_defs.h uses such types
 * as __u64.
 */
#include "bpf_helper_defs.h"

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by libbpf depending on the context (BPF programs, BPF maps,
 * extern variables, etc).
 * To allow use of SEC() with externs (e.g., for extern .maps declarations),
 * make sure __attribute__((unused)) doesn't trigger compilation warning.
 */
#define SEC(name) \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")	    \
	__attribute__((section(name), used))				    \
	_Pragma("GCC diagnostic pop")					    \

/* Avoid 'linux/stddef.h' definition of '__always_inline'. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

/*
 * Use __hidden attribute to mark a non-static BPF subprogram effectively
 * static for BPF verifier's verification algorithm purposes, allowing more
 * extensive and permissive BPF verification process, taking into account
 * subprogram's caller context.
 */
#define __hidden __attribute__((visibility("hidden")))

/* When utilizing vmlinux.h with BPF CO-RE, user BPF programs can't include
 * any system-level headers (such as stddef.h, linux/version.h, etc), and
 * commonly-used macros like NULL and KERNEL_VERSION aren't available through
 * vmlinux.h. This just adds unnecessary hurdles and forces users to re-define
 * them on their own. So as a convenience, provide such definitions here.
 */
#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

/*
 * Helper macros to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)				\
	({							\
		void *__mptr = (void *)(ptr);			\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

/*
 * Helper macro to throw a compilation error if __bpf_unreachable() gets
 * built into the resulting code. This works given BPF back end does not
 * implement __builtin_trap(). This is useful to assert that certain paths
 * of the program code are never used and hence eliminated by the compiler.
 *
 * For example, consider a switch statement that covers known cases used by
 * the program. __bpf_unreachable() can then reside in the default case. If
 * the program gets extended such that a case is not covered in the switch
 * statement, then it will throw a build error due to the default case not
 * being compiled out.
 */
#ifndef __bpf_unreachable
# define __bpf_unreachable()	__builtin_trap()
#endif

/*
 * Helper function to perform a tail call with a constant/immediate map slot.
 */
#if __clang_major__ >= 8 && defined(__bpf__)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 98,
  "endLine": 123,
  "File": "/home/sayandes/opened_extraction/examples/ingress-node-firewall-master/bpf/headers/bpf_helpers.h",
  "funcName": "bpf_tail_call_static",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */"
    },
    {
      "start_line": 5,
      "end_line": 10,
      "text": "/*\n * Note that bpf programs need to include either\n * vmlinux.h (auto-generated from BTF) or linux/types.h\n * in advance since bpf_helper_defs.h uses such types\n * as __u64.\n */"
    },
    {
      "start_line": 17,
      "end_line": 24,
      "text": "/*\n * Helper macro to place programs, maps, license in\n * different sections in elf_bpf file. Section names\n * are interpreted by libbpf depending on the context (BPF programs, BPF maps,\n * extern variables, etc).\n * To allow use of SEC() with externs (e.g., for extern .maps declarations),\n * make sure __attribute__((unused)) doesn't trigger compilation warning.\n */"
    },
    {
      "start_line": 31,
      "end_line": 31,
      "text": "/* Avoid 'linux/stddef.h' definition of '__always_inline'. */"
    },
    {
      "start_line": 42,
      "end_line": 47,
      "text": "/*\n * Use __hidden attribute to mark a non-static BPF subprogram effectively\n * static for BPF verifier's verification algorithm purposes, allowing more\n * extensive and permissive BPF verification process, taking into account\n * subprogram's caller context.\n */"
    },
    {
      "start_line": 50,
      "end_line": 55,
      "text": "/* When utilizing vmlinux.h with BPF CO-RE, user BPF programs can't include\n * any system-level headers (such as stddef.h, linux/version.h, etc), and\n * commonly-used macros like NULL and KERNEL_VERSION aren't available through\n * vmlinux.h. This just adds unnecessary hurdles and forces users to re-define\n * them on their own. So as a convenience, provide such definitions here.\n */"
    },
    {
      "start_line": 64,
      "end_line": 66,
      "text": "/*\n * Helper macros to manipulate data structures\n */"
    },
    {
      "start_line": 78,
      "end_line": 89,
      "text": "/*\n * Helper macro to throw a compilation error if __bpf_unreachable() gets\n * built into the resulting code. This works given BPF back end does not\n * implement __builtin_trap(). This is useful to assert that certain paths\n * of the program code are never used and hence eliminated by the compiler.\n *\n * For example, consider a switch statement that covers known cases used by\n * the program. __bpf_unreachable() can then reside in the default case. If\n * the program gets extended such that a case is not covered in the switch\n * statement, then it will throw a build error due to the default case not\n * being compiled out.\n */"
    },
    {
      "start_line": 94,
      "end_line": 96,
      "text": "/*\n * Helper function to perform a tail call with a constant/immediate map slot.\n */"
    },
    {
      "start_line": 104,
      "end_line": 116,
      "text": "/*\n\t * Provide a hard guarantee that LLVM won't optimize setting r2 (map\n\t * pointer) and r3 (constant map index) from _different paths_ ending\n\t * up at the _same_ call insn as otherwise we won't be able to use the\n\t * jmpq/nopl retpoline-free patching by the x86-64 JIT in the kernel\n\t * given they mismatch. See also d2e4c1e6c294 (\"bpf: Constant map key\n\t * tracking for prog array pokes\") for details on verifier tracking.\n\t *\n\t * Note on clobber list: we need to stay in-line with BPF calling\n\t * convention, so even if we don't end up using r0, r4, r5, we need\n\t * to mark them as clobber so that LLVM doesn't end up using them\n\t * before / after the call.\n\t */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " const void *map",
    " const __u32 slot"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sk_reuseport",
    "sk_skb",
    "cgroup_sock_addr",
    "sched_cls",
    "cgroup_sock",
    "lwt_xmit",
    "sk_msg",
    "flow_dissector",
    "perf_event",
    "xdp",
    "raw_tracepoint",
    "socket_filter",
    "lwt_out",
    "kprobe",
    "lwt_in",
    "lwt_seg6local",
    "cgroup_skb",
    "tracepoint",
    "raw_tracepoint_writable",
    "sock_ops"
  ],
  "source": [
    "static __always_inline void bpf_tail_call_static (void *ctx, const void *map, const __u32 slot)\n",
    "{\n",
    "    if (!__builtin_constant_p (slot))\n",
    "        __bpf_unreachable ();\n",
    "    asm volatile (\"r1 = %[ctx]\\n\\t\"\n",
    "        \"r2 = %[map]\\n\\t\"\n",
    "        \"r3 = %[slot]\\n\\t\"\n",
    "        \"call 12\"\n",
    "        : : [ctx] \"r\"\n",
    "        (ctx), [map] \"r\"\n",
    "        (map), [slot] \"i\"\n",
    "        (slot) : \"r0\",\n",
    "        \"r1\",\n",
    "        \"r2\",\n",
    "        \"r3\",\n",
    "        \"r4\",\n",
    "        \"r5\"\n",
    "        );\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_constant_p",
    "__bpf_unreachable"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static __always_inline void
bpf_tail_call_static(void *ctx, const void *map, const __u32 slot)
{
	if (!__builtin_constant_p(slot))
		__bpf_unreachable();

	/*
	 * Provide a hard guarantee that LLVM won't optimize setting r2 (map
	 * pointer) and r3 (constant map index) from _different paths_ ending
	 * up at the _same_ call insn as otherwise we won't be able to use the
	 * jmpq/nopl retpoline-free patching by the x86-64 JIT in the kernel
	 * given they mismatch. See also d2e4c1e6c294 ("bpf: Constant map key
	 * tracking for prog array pokes") for details on verifier tracking.
	 *
	 * Note on clobber list: we need to stay in-line with BPF calling
	 * convention, so even if we don't end up using r0, r4, r5, we need
	 * to mark them as clobber so that LLVM doesn't end up using them
	 * before / after the call.
	 */
	asm volatile("r1 = %[ctx]\n\t"
		     "r2 = %[map]\n\t"
		     "r3 = %[slot]\n\t"
		     "call 12"
		     :: [ctx]"r"(ctx), [map]"r"(map), [slot]"i"(slot)
		     : "r0", "r1", "r2", "r3", "r4", "r5");
}
#endif

/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	/* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
	LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
	TRI_NO = 0,
	TRI_YES = 1,
	TRI_MODULE = 2,
};

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_fill0(arr, p, x) do {} while (0)
#define ___bpf_fill1(arr, p, x) arr[p] = x
#define ___bpf_fill2(arr, p, x, args...) arr[p] = x; ___bpf_fill1(arr, p + 1, args)
#define ___bpf_fill3(arr, p, x, args...) arr[p] = x; ___bpf_fill2(arr, p + 1, args)
#define ___bpf_fill4(arr, p, x, args...) arr[p] = x; ___bpf_fill3(arr, p + 1, args)
#define ___bpf_fill5(arr, p, x, args...) arr[p] = x; ___bpf_fill4(arr, p + 1, args)
#define ___bpf_fill6(arr, p, x, args...) arr[p] = x; ___bpf_fill5(arr, p + 1, args)
#define ___bpf_fill7(arr, p, x, args...) arr[p] = x; ___bpf_fill6(arr, p + 1, args)
#define ___bpf_fill8(arr, p, x, args...) arr[p] = x; ___bpf_fill7(arr, p + 1, args)
#define ___bpf_fill9(arr, p, x, args...) arr[p] = x; ___bpf_fill8(arr, p + 1, args)
#define ___bpf_fill10(arr, p, x, args...) arr[p] = x; ___bpf_fill9(arr, p + 1, args)
#define ___bpf_fill11(arr, p, x, args...) arr[p] = x; ___bpf_fill10(arr, p + 1, args)
#define ___bpf_fill12(arr, p, x, args...) arr[p] = x; ___bpf_fill11(arr, p + 1, args)
#define ___bpf_fill(arr, args...) \
	___bpf_apply(___bpf_fill, ___bpf_narg(args))(arr, 0, args)

/*
 * BPF_SEQ_PRINTF to wrap bpf_seq_printf to-be-printed values
 * in a structure.
 */
#define BPF_SEQ_PRINTF(seq, fmt, args...)			\
({								\
	static const char ___fmt[] = fmt;			\
	unsigned long long ___param[___bpf_narg(args)];		\
								\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	\
	___bpf_fill(___param, args);				\
	_Pragma("GCC diagnostic pop")				\
								\
	bpf_seq_printf(seq, ___fmt, sizeof(___fmt),		\
		       ___param, sizeof(___param));		\
})

/*
 * BPF_SNPRINTF wraps the bpf_snprintf helper with variadic arguments instead of
 * an array of u64.
 */
#define BPF_SNPRINTF(out, out_size, fmt, args...)		\
({								\
	static const char ___fmt[] = fmt;			\
	unsigned long long ___param[___bpf_narg(args)];		\
								\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	\
	___bpf_fill(___param, args);				\
	_Pragma("GCC diagnostic pop")				\
								\
	bpf_snprintf(out, out_size, ___fmt,			\
		     ___param, sizeof(___param));		\
})

#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD
#else
#define BPF_PRINTK_FMT_MOD static const
#endif

#define __bpf_printk(fmt, ...)				\
({							\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

/*
 * __bpf_vprintk wraps the bpf_trace_vprintk helper with variadic arguments
 * instead of an array of u64.
 */
#define __bpf_vprintk(fmt, args...)				\
({								\
	static const char ___fmt[] = fmt;			\
	unsigned long long ___param[___bpf_narg(args)];		\
								\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")	\
	___bpf_fill(___param, args);				\
	_Pragma("GCC diagnostic pop")				\
								\
	bpf_trace_vprintk(___fmt, sizeof(___fmt),		\
			  ___param, sizeof(___param));		\
})

/* Use __bpf_printk when bpf_printk call has 3 or fewer fmt args
 * Otherwise use __bpf_vprintk
 */
#define ___bpf_pick_printk(...) \
	___bpf_nth(_, ##__VA_ARGS__, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,	\
		   __bpf_vprintk, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,		\
		   __bpf_vprintk, __bpf_vprintk, __bpf_printk /*3*/, __bpf_printk /*2*/,\
		   __bpf_printk /*1*/, __bpf_printk /*0*/)

/* Helper macro to print out debug messages */

/* #define DEBUG */
#ifdef DEBUG
#define bpf_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)
#else
#define bpf_printk(fmt, args...)
#endif
#endif
