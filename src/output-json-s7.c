/* Copyright (C) 2018 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-s7.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer S7.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-s7.h"
#include "output-json-s7.h"

#include "rust-applayers7-logger-gen.h"

typedef struct LogS7FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogS7FileCtx;

typedef struct LogS7LogThread_ {
    LogS7FileCtx *s7log_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogS7LogThread;

static int JsonS7Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonS7Logger");
    LogS7LogThread *thread = thread_data;

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "s7");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *s7_js = rs_s7_logger_log(tx);
    if (unlikely(s7_js == NULL)) {
        goto error;
    }
    json_object_set_new(js, "s7", s7_js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->s7log_ctx->file_ctx, &thread->buffer);
    json_decref(js);

    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputS7LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogS7FileCtx *s7log_ctx = (LogS7FileCtx *)output_ctx->data;
    SCFree(s7log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputS7LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogS7FileCtx *s7log_ctx = SCCalloc(1, sizeof(*s7log_ctx));
    if (unlikely(s7log_ctx == NULL)) {
        return result;
    }
    s7log_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(s7log_ctx);
        return result;
    }
    output_ctx->data = s7log_ctx;
    output_ctx->DeInit = OutputS7LogDeInitCtxSub;

    SCLogNotice("S7 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_S7);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonS7LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogS7LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogS7.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->s7log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonS7LogThreadDeinit(ThreadVars *t, void *data)
{
    LogS7LogThread *thread = (LogS7LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonS7LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_S7, "eve-log",
        "JsonS7Log", "eve-log.s7",
        OutputS7LogInitSub, ALPROTO_S7, JsonS7Logger,
        JsonS7LogThreadInit, JsonS7LogThreadDeinit, NULL);

    SCLogNotice("S7 JSON logger registered.");
}
