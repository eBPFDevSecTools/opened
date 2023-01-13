/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef _LINUX_BYTEORDER_LITTLE_ENDIAN_H
#define _LINUX_BYTEORDER_LITTLE_ENDIAN_H

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include <linux/types.h>
#include <linux/swab.h>

#define __constant_htonl(x) ((__be32)___constant_swab32((x)))
#define __constant_ntohl(x) ___constant_swab32((__be32)(x))
#define __constant_htons(x) ((__be16)___constant_swab16((x)))
#define __constant_ntohs(x) ___constant_swab16((__be16)(x))
#define __constant_cpu_to_le64(x) ((__le64)(__u64)(x))
#define __constant_le64_to_cpu(x) ((__u64)(__le64)(x))
#define __constant_cpu_to_le32(x) ((__le32)(__u32)(x))
#define __constant_le32_to_cpu(x) ((__u32)(__le32)(x))
#define __constant_cpu_to_le16(x) ((__le16)(__u16)(x))
#define __constant_le16_to_cpu(x) ((__u16)(__le16)(x))
#define __constant_cpu_to_be64(x) ((__be64)___constant_swab64((x)))
#define __constant_be64_to_cpu(x) ___constant_swab64((__u64)(__be64)(x))
#define __constant_cpu_to_be32(x) ((__be32)___constant_swab32((x)))
#define __constant_be32_to_cpu(x) ___constant_swab32((__u32)(__be32)(x))
#define __constant_cpu_to_be16(x) ((__be16)___constant_swab16((x)))
#define __constant_be16_to_cpu(x) ___constant_swab16((__u16)(__be16)(x))
#define __cpu_to_le64(x) ((__le64)(__u64)(x))
#define __le64_to_cpu(x) ((__u64)(__le64)(x))
#define __cpu_to_le32(x) ((__le32)(__u32)(x))
#define __le32_to_cpu(x) ((__u32)(__le32)(x))
#define __cpu_to_le16(x) ((__le16)(__u16)(x))
#define __le16_to_cpu(x) ((__u16)(__le16)(x))
#define __cpu_to_be64(x) ((__be64)__swab64((x)))
#define __be64_to_cpu(x) __swab64((__u64)(__be64)(x))
#define __cpu_to_be32(x) ((__be32)__swab32((x)))
#define __be32_to_cpu(x) __swab32((__u32)(__be32)(x))
#define __cpu_to_be16(x) ((__be16)__swab16((x)))
#define __be16_to_cpu(x) __swab16((__u16)(__be16)(x))

/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 45,
 Endline: 48,
 Funcname: __cpu_to_le64p,
 Input: (const __u64 *p),
 Output: static__inline____le64,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __le64 __cpu_to_le64p(const __u64 *p)
{
	return (__le64)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 49,
 Endline: 52,
 Funcname: __le64_to_cpup,
 Input: (const __le64 *p),
 Output: static__inline____u64,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u64 __le64_to_cpup(const __le64 *p)
{
	return (__u64)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 53,
 Endline: 56,
 Funcname: __cpu_to_le32p,
 Input: (const __u32 *p),
 Output: static__inline____le32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __le32 __cpu_to_le32p(const __u32 *p)
{
	return (__le32)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 57,
 Endline: 60,
 Funcname: __le32_to_cpup,
 Input: (const __le32 *p),
 Output: static__inline____u32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u32 __le32_to_cpup(const __le32 *p)
{
	return (__u32)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 61,
 Endline: 64,
 Funcname: __cpu_to_le16p,
 Input: (const __u16 *p),
 Output: static__inline____le16,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __le16 __cpu_to_le16p(const __u16 *p)
{
	return (__le16)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 65,
 Endline: 68,
 Funcname: __le16_to_cpup,
 Input: (const __le16 *p),
 Output: static__inline____u16,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u16 __le16_to_cpup(const __le16 *p)
{
	return (__u16)*p;
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 69,
 Endline: 72,
 Funcname: __cpu_to_be64p,
 Input: (const __u64 *p),
 Output: static__inline____be64,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __be64 __cpu_to_be64p(const __u64 *p)
{
	return (__be64)__swab64p(p);
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 73,
 Endline: 76,
 Funcname: __be64_to_cpup,
 Input: (const __be64 *p),
 Output: static__inline____u64,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u64 __be64_to_cpup(const __be64 *p)
{
	return __swab64p((__u64 *)p);
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 77,
 Endline: 80,
 Funcname: __cpu_to_be32p,
 Input: (const __u32 *p),
 Output: static__inline____be32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __be32 __cpu_to_be32p(const __u32 *p)
{
	return (__be32)__swab32p(p);
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 81,
 Endline: 84,
 Funcname: __be32_to_cpup,
 Input: (const __be32 *p),
 Output: static__inline____u32,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u32 __be32_to_cpup(const __be32 *p)
{
	return __swab32p((__u32 *)p);
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 85,
 Endline: 88,
 Funcname: __cpu_to_be16p,
 Input: (const __u16 *p),
 Output: static__inline____be16,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __be16 __cpu_to_be16p(const __u16 *p)
{
	return (__be16)__swab16p(p);
}
/* 
 OPENED COMMENT BEGIN 
 { 
 File: /home/sayandes/opened_extraction/examples/cilium/include/linux/byteorder/little_endian.h,
 Startline: 89,
 Endline: 92,
 Funcname: __be16_to_cpup,
 Input: (const __be16 *p),
 Output: static__inline____u16,
 Helpers: [],
 Read_maps: [],
 Update_maps: [],
 Func Description: TO BE ADDED, 
 Commentor: TO BE ADDED (<name>,<email>) 
 } 
 OPENED COMMENT END 
 */ 
static __inline__ __u16 __be16_to_cpup(const __be16 *p)
{
	return __swab16p((__u16 *)p);
}
#define __cpu_to_le64s(x) do { (void)(x); } while (0)
#define __le64_to_cpus(x) do { (void)(x); } while (0)
#define __cpu_to_le32s(x) do { (void)(x); } while (0)
#define __le32_to_cpus(x) do { (void)(x); } while (0)
#define __cpu_to_le16s(x) do { (void)(x); } while (0)
#define __le16_to_cpus(x) do { (void)(x); } while (0)
#define __cpu_to_be64s(x) __swab64s((x))
#define __be64_to_cpus(x) __swab64s((x))
#define __cpu_to_be32s(x) __swab32s((x))
#define __be32_to_cpus(x) __swab32s((x))
#define __cpu_to_be16s(x) __swab16s((x))
#define __be16_to_cpus(x) __swab16s((x))


#endif /* _LINUX_BYTEORDER_LITTLE_ENDIAN_H */
