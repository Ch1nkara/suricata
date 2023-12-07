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

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "s7" keyword to allow detection.
 * This imply registering to the detect engine and
 * calling the following rust function:
 *   - suricata rules parser
 *   - matching a rule signature and a transaction
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


#ifdef UNITTESTS
static void DetectS7S7RegisterTests(void);
#endif
static int g_s7_rust_id = 0;

/** \internal
 *
 * \brief this function will free memory associated with DetectS7
 *
 * \param ptr pointer to DetectS7
 */
static void DetectS7Free(DetectEngineCtx *de_ctx, void *ptr) {
    SCEnter();
    if (ptr != NULL) {
        rs_s7_free(ptr);
    }
    SCReturn;
}

/** \internal
 *
 * \brief this function is used to add the parsed "id" option into the current signature
 *
 * \param de_ctx    Pointer to the Detection Engine Context
 * \param s         Pointer to the Current Signature
 * \param str       Pointer to the user provided "id" option
 *
 * \retval 0 on Success or -1 on Failure
 */
static int DetectS7S7Setup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    S7CommSignature *s7 = NULL;
    SigMatch        *sm = NULL;
    s->init_data->list = g_s7_rust_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_S7) != 0)
        return -1;

    if ((s7 = rs_s7_parse(str, s7)) == NULL) {
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
    if (s7 != NULL)
        DetectS7Free(de_ctx, s7);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \internal
 * \brief Function to match a S7 transaction to a rule signature
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into uint8_t.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectS7Match(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return rs_s7_inspect(txv, (void *)ctx);
}

/**
 * \brief Registration function for s7 keyword
 */
void DetectS7S7Register(void)
{
    sigmatch_table[DETECT_AL_S7_S7].name = "s7";
    sigmatch_table[DETECT_AL_S7_S7].desc =
            "S7 content modifier to match on the s7 buffers";
    sigmatch_table[DETECT_AL_S7_S7].Setup = DetectS7S7Setup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_S7_S7].RegisterTests = DetectS7S7RegisterTests;
#endif
    sigmatch_table[DETECT_AL_S7_S7].Match = NULL;
    sigmatch_table[DETECT_AL_S7_S7].AppLayerTxMatch = DetectS7Match;
    sigmatch_table[DETECT_AL_S7_S7].Free = DetectS7Free;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("s7_buffer", ALPROTO_S7, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_s7_rust_id = DetectBufferTypeGetByName("s7_buffer");

    SCLogNotice("S7 application layer detect registered.");
}

//TODO Unit tests
