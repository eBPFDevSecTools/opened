/* Copyright (C) 2007-2017 Open Information Security Foundation
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

#include "../suricata-common.h"
#include "../stream-tcp-private.h"
#include "../stream-tcp.h"
#include "../stream-tcp-reassemble.h"
#include "../stream-tcp-inline.h"
#include "../stream-tcp-list.h"
#include "../stream-tcp-util.h"
#include "../util-streaming-buffer.h"
#include "../util-print.h"
#include "../util-unittest.h"

static int VALIDATE(TcpStream *stream, uint8_t *data, uint32_t data_len)
{
    if (StreamingBufferCompareRawData(&stream->sb,
                data, data_len) == 0)
    {
        SCReturnInt(0);
    }
    SCLogInfo("OK");
    PrintRawDataFp(stdout, data, data_len);
    return 1;
}

#define INLINE_START(isn)                      \
    Packet *p;                                  \
    TcpReassemblyThreadCtx *ra_ctx = NULL;      \
    TcpSession ssn;                             \
    ThreadVars tv;                              \
    memset(&tv, 0, sizeof(tv));                 \
    \
    StreamTcpUTInit(&ra_ctx);                   \
    StreamTcpUTInitInline();                    \
    \
    StreamTcpUTSetupSession(&ssn);              \
    StreamTcpUTSetupStream(&ssn.server, (isn)); \
    StreamTcpUTSetupStream(&ssn.client, (isn)); \
    \
    TcpStream *stream = &ssn.client;

#define INLINE_END                             \
    StreamTcpUTClearSession(&ssn);              \
    StreamTcpUTDeinit(ra_ctx);                  \
    PASS

#define INLINE_ADD_PAYLOAD(rseq, seg, seglen, packet, packetlen)                                   \
    p = UTHBuildPacketReal(                                                                        \
            (uint8_t *)(seg), (seglen), IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);              \
    FAIL_IF(p == NULL);                                                                            \
    p->tcph->th_seq = htonl(stream->isn + (rseq));                                                 \
    p->tcph->th_ack = htonl(31);                                                                   \
    FAIL_IF(StreamTcpReassembleHandleSegmentHandleData(&tv, ra_ctx, &ssn, stream, p) < 0);         \
    FAIL_IF(memcmp(p->payload, packet, MIN((packetlen), p->payload_len)) != 0);                    \
    UTHFreePacket(p);

#define INLINE_STEP(rseq, seg, seglen, buf, buflen, packet, packetlen)                             \
    INLINE_ADD_PAYLOAD((rseq), (seg), (seglen), (packet), (packetlen));                            \
    FAIL_IF(!(VALIDATE(stream, (uint8_t *)(buf), (buflen))));

int UTHCheckGapAtPostion(TcpStream *stream, int pos, uint64_t offset, uint32_t len);
int UTHCheckDataAtPostion(
        TcpStream *stream, int pos, uint64_t offset, const char *data, uint32_t len);

/** \test full overlap */
static int StreamTcpInlineTest01(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "AAC", 3, "AAC", 3, "AAC", 3);
    INLINE_STEP(1, "ABC", 3, "AAC", 3, "AAC", 3);
    INLINE_END;
}

/** \test full overlap */
static int StreamTcpInlineTest02(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "ABCDE", 5, "ABCDE", 5, "ABCDE", 5);
    INLINE_STEP(2, "xxx", 3, "ABCDE", 5, "BCD", 3);
    INLINE_END;
}

/** \test partial overlap */
static int StreamTcpInlineTest03(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "ABCDE", 5, "ABCDE", 5, "ABCDE", 5);
    INLINE_STEP(3, "xxxxx", 5, "ABCDExx", 7, "CDExx", 5);
    INLINE_END;
}

/** \test partial overlap */
static int StreamTcpInlineTest04(void)
{
    INLINE_START(0);
    INLINE_ADD_PAYLOAD(3, "ABCDE", 5, "ABCDE", 5);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 2) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 2, "ABCDE", 5) == 1);
    INLINE_STEP(1, "xxxxx", 5, "xxABCDE", 7, "xxABC", 5);
    INLINE_END;
}

/** \test no overlap */
static int StreamTcpInlineTest05(void)
{
    INLINE_START(0);
    INLINE_ADD_PAYLOAD(8, "ABCDE", 5, "ABCDE", 5);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 7) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 7, "ABCDE", 5) == 1);
    INLINE_ADD_PAYLOAD(1, "xxxxx", 5, "xxxxx", 5);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 0, 0, "xxxxx", 5) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 1, 5, 2) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 2, 7, "ABCDE", 5) == 1);
    INLINE_END;
}

/** \test multiple overlaps */
static int StreamTcpInlineTest06(void)
{
    INLINE_START(0);
    INLINE_ADD_PAYLOAD(2, "A", 1, "A", 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 1, "A", 1) == 1);
    INLINE_ADD_PAYLOAD(4, "A", 1, "A", 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 1, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 2, 2, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 3, 3, "A", 1) == 1);
    INLINE_ADD_PAYLOAD(6, "A", 1, "A", 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 1, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 2, 2, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 3, 3, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 4, 4, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 5, 5, "A", 1) == 1);
    INLINE_ADD_PAYLOAD(8, "A", 1, "A", 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 1, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 2, 2, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 3, 3, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 4, 4, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 5, 5, "A", 1) == 1);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 6, 6, 1) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 7, 7, "A", 1) == 1);
    INLINE_STEP(1, "xxxxxxxxx", 9, "xAxAxAxAx", 9, "xAxAxAxAx", 9);
    INLINE_END;
}

/** \test overlap, data not different */
static int StreamTcpInlineTest07(void)
{
    INLINE_START(0);
    INLINE_ADD_PAYLOAD(3, "ABCDE", 5, "ABCDE", 5);
    FAIL_IF_NOT(UTHCheckGapAtPostion(stream, 0, 0, 2) == 1);
    FAIL_IF_NOT(UTHCheckDataAtPostion(stream, 1, 2, "ABCDE", 5) == 1);
    INLINE_STEP(1, "XXABC", 5, "XXABCDE", 7, "XXABC", 5);
    INLINE_END;
}

static int StreamTcpInlineTest08(void)
{
    INLINE_START(0);
    INLINE_STEP(1, "AAAAA", 5, "AAAAA", 5, "AAAAA", 5);
    INLINE_STEP(1, "BBBBB", 5, "AAAAA", 5, "AAAAA", 5);
    INLINE_STEP(1, "CCCCCCCCCC", 10, "AAAAACCCCC", 10, "AAAAACCCCC", 10);
    INLINE_STEP(10, "X", 1, "AAAAACCCCC", 10, "C", 1);
    INLINE_STEP(11, "X", 1, "AAAAACCCCCX", 11, "X", 1);
    INLINE_END;
}

void StreamTcpInlineRegisterTests(void)
{
    UtRegisterTest("StreamTcpInlineTest01", StreamTcpInlineTest01);
    UtRegisterTest("StreamTcpInlineTest02", StreamTcpInlineTest02);
    UtRegisterTest("StreamTcpInlineTest03", StreamTcpInlineTest03);
    UtRegisterTest("StreamTcpInlineTest04", StreamTcpInlineTest04);
    UtRegisterTest("StreamTcpInlineTest05", StreamTcpInlineTest05);
    UtRegisterTest("StreamTcpInlineTest06", StreamTcpInlineTest06);
    UtRegisterTest("StreamTcpInlineTest07", StreamTcpInlineTest07);
    UtRegisterTest("StreamTcpInlineTest08", StreamTcpInlineTest08);
}
