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
 * TODO: Update \author in this file and app-layer-s7rust.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * S7 application layer detector and parser for learning and
 * s7rust pruposes.
 *
 * This s7rust implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-s7.h"

#include "rust-applayers7-s7-gen.h"

void RegisterS7Parsers(void)
{
    SCLogNotice("Registring Rust s7 parser.");
    rs_s7_register_parser();
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_S7,
        S7ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void S7ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
