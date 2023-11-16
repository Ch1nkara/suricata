/* Copyright (C) 2023 Open Information Security Foundation
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

/*
 * TODO: Update the \author in this file and detect-s7.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "s7_rust" keyword to allow content
 * inspections on the decoded s7 application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-s7-s7.h"
#include "app-layer-parser.h"
#include "detect-engine-build.h"
#include "rust.h"

static int DetectS7S7Setup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectS7S7RegisterTests(void);
#endif
static int g_s7_rust_id = 0;

static int DetectS7Match(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return rs_s7_inspect(txv, (void *)ctx);
}

/** \internal
 *
 * \brief this function will free memory associated with DetectModbus
 *
 * \param ptr pointer to DetectModbus
 */
static void DetectS7Free(DetectEngineCtx *de_ctx, void *ptr) {
    SCEnter();
    if (ptr != NULL) {
        rs_s7_free(ptr);
    }
    SCReturn;
}

void DetectS7S7Register(void)
{
    sigmatch_table[DETECT_AL_S7_S7].name = "s7";
    sigmatch_table[DETECT_AL_S7_S7].desc =
            "S7 content modifier to match on the s7 buffers";
    sigmatch_table[DETECT_AL_S7_S7].Setup = DetectS7S7Setup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_S7_S7].RegisterTests = DetectS7S7RegisterTests;
#endif
    //sigmatch_table[DETECT_AL_S7_S7].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_S7_S7].Match = NULL;
    sigmatch_table[DETECT_AL_S7_S7].AppLayerTxMatch = DetectS7Match;
    sigmatch_table[DETECT_AL_S7_S7].Free = DetectS7Free;


    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("s7_buffer", ALPROTO_S7, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);
    //DetectAppLayerInspectEngineRegister2("s7_buffer", ALPROTO_S7, SIG_FLAG_TOCLIENT, 0,
            //DetectEngineInspectGenericList, NULL);

    g_s7_rust_id = DetectBufferTypeGetByName("s7_buffer");

    SCLogNotice("S7 application layer detect registered.");
}

static int DetectS7S7Setup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectS7Signature *s7 = NULL;
    SigMatch        *sm = NULL;
    s->init_data->list = g_s7_rust_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_S7) != 0)
        return -1;

    if ((s7 = rs_s7_parse(str)) == NULL) {
        SCLogError("invalid s7 option");
        goto error;
    }

    sm = SigMatchAlloc();
        if (sm == NULL)
        goto error;

    sm->type    = DETECT_AL_S7_S7;
    sm->ctx     = (void *) s7;

    SigMatchAppendSMToList(s, sm, g_s7_rust_id);

    SCReturnInt(0);
error:
    SCReturnInt(-1);
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"
#include "stream-tcp.h"
#include "detect-engine-alert.h"

static int DetectS7S7Test(void)
{
    PASS;
}

static void DetectS7S7RegisterTests(void)
{
    UtRegisterTest("DetectS7S7Test", DetectS7S7Test);
}
#endif /* UNITTESTS */
