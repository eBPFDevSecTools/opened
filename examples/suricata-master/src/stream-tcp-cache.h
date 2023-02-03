/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __STREAM_TCP_CACHE_H__
#define __STREAM_TCP_CACHE_H__

#include "stream-tcp-private.h"

void StreamTcpThreadCacheEnable(void);
void StreamTcpThreadCacheReturnSegment(TcpSegment *seg);
void StreamTcpThreadCacheReturnSession(TcpSession *ssn);
void StreamTcpThreadCacheCleanup(void);

TcpSegment *StreamTcpThreadCacheGetSegment(void);
TcpSession *StreamTcpThreadCacheGetSession(void);

#endif /* __STREAM_TCP_CACHE_H__ */
