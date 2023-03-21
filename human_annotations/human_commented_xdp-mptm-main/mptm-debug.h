/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Authors by:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */

#ifndef __MPTM_DEBUG_H__
#define __MPTM_DEBUG_H__

#include <linux/bpf.h>

#ifndef bpf_debug
#define bpf_debug(fmt, ...) \
({ \
const char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

#ifdef __MPTM_DEBUG__
#define mptm_debug(tn, ...) \
do { if (tn && tn->debug) {       \
        bpf_debug(##__VA_ARGS__); \
     }                            \
} while (0)
#else
#define mptm_debug(...)
#endif

#ifdef __MPTM_DEBUG__
#define mptm_print(...) bpf_debug(__VA_ARGS__)
#else
#define mptm_print(...)
#endif

#endif /* __MPTM_DEBUG_H__ */