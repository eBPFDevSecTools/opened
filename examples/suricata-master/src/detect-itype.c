/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 *
 * Implements itype keyword support
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-itype.h"
#include "detect-engine-uint.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"


static int DetectITypeMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectITypeSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectITypeRegisterTests(void);
#endif
void DetectITypeFree(DetectEngineCtx *, void *);

static int PrefilterSetupIType(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterITypeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for itype: keyword
 */
void DetectITypeRegister (void)
{
    sigmatch_table[DETECT_ITYPE].name = "itype";
    sigmatch_table[DETECT_ITYPE].desc = "match on a specific ICMP type";
    sigmatch_table[DETECT_ITYPE].url = "/rules/header-keywords.html#itype";
    sigmatch_table[DETECT_ITYPE].Match = DetectITypeMatch;
    sigmatch_table[DETECT_ITYPE].Setup = DetectITypeSetup;
    sigmatch_table[DETECT_ITYPE].Free = DetectITypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ITYPE].RegisterTests = DetectITypeRegisterTests;
#endif
    sigmatch_table[DETECT_ITYPE].SupportsPrefilter = PrefilterITypeIsPrefilterable;
    sigmatch_table[DETECT_ITYPE].SetupPrefilter = PrefilterSetupIType;
}

/**
 * \brief This function is used to match itype rule option set on a packet with those passed via
 * itype:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectITypeMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t pitype;
    if (PKT_IS_ICMPV4(p)) {
        pitype = ICMPV4_GET_TYPE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        pitype = ICMPV6_GET_TYPE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return 0;
    }

    const DetectU8Data *itd = (const DetectU8Data *)ctx;
    return DetectU8Match(pitype, itd);
}

/**
 * \brief This function is used to parse itype options passed via itype: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param itypestr Pointer to the user provided itype options
 *
 * \retval itd pointer to DetectU8Data on success
 * \retval NULL on failure
 */
static DetectU8Data *DetectITypeParse(DetectEngineCtx *de_ctx, const char *itypestr)
{
    return DetectU8Parse(itypestr);
}

/**
 * \brief this function is used to add the parsed itype data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param itypestr pointer to the user provided itype options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectITypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *itypestr)
{

    DetectU8Data *itd = NULL;
    SigMatch *sm = NULL;

    itd = DetectITypeParse(de_ctx, itypestr);
    if (itd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ITYPE;
    sm->ctx = (SigMatchCtx *)itd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (itd != NULL) DetectITypeFree(de_ctx, itd);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectITypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectU8Data *itd = (DetectU8Data *)ptr;
    rs_detect_u8_free(itd);
}

/* prefilter code
 *
 * Prefilter uses the U8Hash logic, where we setup a 256 entry array
 * for each ICMP type. Each array element has the list of signatures
 * that need to be inspected. */

static void PrefilterPacketITypeMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t pitype;
    if (PKT_IS_ICMPV4(p)) {
        pitype = ICMPV4_GET_TYPE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        pitype = ICMPV6_GET_TYPE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return;
    }

    const PrefilterPacketU8HashCtx *h = pectx;
    const SigsArray *sa = h->array[pitype];
    if (sa) {
        PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
    }
}

static int PrefilterSetupIType(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_ITYPE, PrefilterPacketU8Set,
            PrefilterPacketU8Compare, PrefilterPacketITypeMatch);
}

static bool PrefilterITypeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ITYPE:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS

#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectITypeParseTest01 is a test for setting a valid itype value
 */
static int DetectITypeParseTest01(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "8");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_EQ);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest02 is a test for setting a valid itype value
 *       with ">" operator
 */
static int DetectITypeParseTest02(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, ">8");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_GT);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest03 is a test for setting a valid itype value
 *       with "<" operator
 */
static int DetectITypeParseTest03(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "<8");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_LT);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest04 is a test for setting a valid itype value
 *       with "<>" operator
 */
static int DetectITypeParseTest04(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "8<>20");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->arg2 == 20);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_RA);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest05 is a test for setting a valid itype value
 *       with spaces all around
 */
static int DetectITypeParseTest05(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "   8 ");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_EQ);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest06 is a test for setting a valid itype value
 *       with ">" operator and spaces all around
 */
static int DetectITypeParseTest06(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "  >  8  ");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_GT);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest07 is a test for setting a valid itype value
 *       with "<>" operator and spaces all around
 */
static int DetectITypeParseTest07(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "  8  <> 20  ");
    FAIL_IF_NULL(itd);
    FAIL_IF_NOT(itd->arg1 == 8);
    FAIL_IF_NOT(itd->arg2 == 20);
    FAIL_IF_NOT(itd->mode == DETECT_UINT_RA);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \test DetectITypeParseTest08 is a test for setting an invalid itype value
 */
static int DetectITypeParseTest08(void)
{
    DetectU8Data *itd = NULL;
    itd = DetectITypeParse(NULL, "> 8 <> 20");
    FAIL_IF_NOT_NULL(itd);
    DetectITypeFree(NULL, itd);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectIType
 */
void DetectITypeRegisterTests(void)
{
    UtRegisterTest("DetectITypeParseTest01", DetectITypeParseTest01);
    UtRegisterTest("DetectITypeParseTest02", DetectITypeParseTest02);
    UtRegisterTest("DetectITypeParseTest03", DetectITypeParseTest03);
    UtRegisterTest("DetectITypeParseTest04", DetectITypeParseTest04);
    UtRegisterTest("DetectITypeParseTest05", DetectITypeParseTest05);
    UtRegisterTest("DetectITypeParseTest06", DetectITypeParseTest06);
    UtRegisterTest("DetectITypeParseTest07", DetectITypeParseTest07);
    UtRegisterTest("DetectITypeParseTest08", DetectITypeParseTest08);
}
#endif /* UNITTESTS */
