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
 * TODO: Update \author in this file and in output-json-s8.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer S8.
 */

#include "suricata-common.h"
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

#include "output-json-s8.h"
#include "rust.h"

typedef struct LogS8FileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogS8FileCtx;

typedef struct LogS8LogThread_ {
    LogS8FileCtx *s8log_ctx;
    OutputJsonThreadCtx *ctx;
} LogS8LogThread;

static int JsonS8Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonS8Logger");
    LogS8LogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "s8", NULL, thread->s8log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "s8");
    if (!rs_s8_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputS8LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogS8FileCtx *s8log_ctx = (LogS8FileCtx *)output_ctx->data;
    SCFree(s8log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputS8LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogS8FileCtx *s8log_ctx = SCCalloc(1, sizeof(*s8log_ctx));
    if (unlikely(s8log_ctx == NULL)) {
        return result;
    }
    s8log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(s8log_ctx);
        return result;
    }
    output_ctx->data = s8log_ctx;
    output_ctx->DeInit = OutputS8LogDeInitCtxSub;

    SCLogNotice("S8 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_S8);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonS8LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogS8LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogS8.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->s8log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->s8log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonS8LogThreadDeinit(ThreadVars *t, void *data)
{
    LogS8LogThread *thread = (LogS8LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonS8LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonS8Log", "eve-log.s8",
            OutputS8LogInitSub, ALPROTO_S8, JsonS8Logger,
            JsonS8LogThreadInit, JsonS8LogThreadDeinit, NULL);

    SCLogNotice("S8 JSON logger registered.");
}
