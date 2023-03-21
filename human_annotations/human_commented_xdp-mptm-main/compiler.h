/* SPDX-License-Identifier: GPL-2.0-or-later
 * 
 * Authors:
 * Dushyant Behl <dushyantbehl@in.ibm.com>
 * Sayandeep Sen <sayandes@in.ibm.com>
 * Palanivel Kodeswaran <palani.kodeswaran@in.ibm.com>
 */
#pragma once

#ifndef __COMPILER_H__
#define __COMPILER_H__

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#ifndef __ALWAYS_INLINE__
#define __ALWAYS_INLINE__ __attribute__((__always_inline__))
#endif

#ifndef likely
# define likely(x)      __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)    __builtin_expect(!!(x), 0)
#endif

#endif
