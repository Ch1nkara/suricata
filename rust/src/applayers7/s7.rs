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

use std;
use crate::core::{self, ALPROTO_UNKNOWN, AppProto, Flow, IPPROTO_TCP};
use std::mem::transmute;
use crate::applayer::{self, LoggerFlags};
use crate::parser::*;
use std::ffi::CString;
use nom;
use super::parser;
use super::s7_constant::{S7Comm};
use super::s7_constant::{
    INIT_FRAME_LENGTH, INIT_TPKT_VERSION, INIT_TPKT_RESERVED,
    INIT_TPKT_INIT_LENGTH_1, INIT_TPKT_INIT_LENGTH_2,
    COTP_CONNECT_REQUEST, COTP_CONNECT_CONFIRM, S7_PROTOCOLE_ID,
    COTP_HEADER_LENGTH,TPKT_HEADER_LENGTH
};

static mut ALPROTO_S7: AppProto = ALPROTO_UNKNOWN;

#[derive(Debug)]
pub struct S7Transaction {
    tx_id: u64,
    pub request: Option<S7Comm>,
    pub response: Option<S7Comm>,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
}

impl S7Transaction {
    pub fn new() -> S7Transaction {
        S7Transaction {
            tx_id: 0,
            request: None,
            response: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for S7Transaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct S7State {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    transactions: Vec<S7Transaction>,
}

impl S7State {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            transactions: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&S7Transaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> S7Transaction {
        let mut tx = S7Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut S7Transaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        /* handle non s7 parasite frames such as cotp handshakes*/
        if is_malformed_s7(input) {
            return true
        }

        match parser::s7_parse_message(input) {
            Ok((_rem, request)) => {
                SCLogNotice!("Parsing request ok: {:?}", request);
                let mut tx = self.new_tx();
                tx.request = Some(request);
                self.transactions.push(tx);
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogNotice!("Parsing response failed: ERR Incomplete");
                return false;
            }
            Err(_) => {
                                return false;
            }
        }

        /* Input was fully consumed. */
        return true;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        /* handle non s7 parasite frames such as cotp handshakes*/
        if is_malformed_s7(input) {
            return true
        }

        match parser::s7_parse_message(input) {
            Ok((_rem, response)) => {
                SCLogNotice!("Parsing response ok: {:?}", response);
                if let Some(tx) = self.find_request() {
                    tx.response = Some(response);
                    SCLogNotice!("Found response for request");
                }
            }
            Err(nom::Err::Incomplete(_)) => {
                SCLogNotice!("Parsing response failed: ERR Incomplete");
                return false;
            }
            Err(err) => {
                SCLogNotice!("Parsing response failed: {}", err);
                return false;
            }
        }

                return true;
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&S7Transaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

/* Probe for a s7 protocol. Since S7 is built on top of COTP,
*  tcp connection is considered using s7 protocol if :
*   - on port 102
*   - valid COTP connection on top of TCP 
* Not perfect but sufficient */
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    SCLogNotice!("in prober function");
    /* fail probe if PDU not the right size for comm setup */
    if ! input.len() == INIT_FRAME_LENGTH { 
        return Err(nom::Err::Error(nom::Context::Code(input, nom::ErrorKind::Eof)))
    }

    let (cotp_payload, tpkt_payload) = nom::take!(input, 4_usize)?;

    /* fail probe if not the proper COTP initialisation */
    if tpkt_payload != [INIT_TPKT_VERSION, 
                        INIT_TPKT_RESERVED, 
                        INIT_TPKT_INIT_LENGTH_1, 
                        INIT_TPKT_INIT_LENGTH_2] || 
       (cotp_payload[1] != COTP_CONNECT_REQUEST && cotp_payload[1] != COTP_CONNECT_CONFIRM)
    {
        return Err(nom::Err::Error(nom::Context::Code(input, nom::ErrorKind::Verify)))
    }

    SCLogNotice!("SUCCESS");
    return Ok((&[], ()))
}

fn is_malformed_s7(input: &[u8]) -> bool{
    //SCLogNotice!("malformed input: {:x?}", input);
    /* Not interested in frames that contain only TPKT and COTP headers
    *  but no S7 PDU */
    if input.len() <= COTP_HEADER_LENGTH + TPKT_HEADER_LENGTH {
        SCLogNotice!("req_parsing DONE, too short, length: {}", input.len());
        return true;
    }
    /* Final check to verify that this is a s7 frame */
    if input[COTP_HEADER_LENGTH + TPKT_HEADER_LENGTH] != S7_PROTOCOLE_ID {
        SCLogNotice!("req_parsing DONE, wrong protocol, id: {:x?}", input[COTP_HEADER_LENGTH + TPKT_HEADER_LENGTH]);
        return true;
    }
    return false;
}

// C exports.

export_tx_get_detect_state!(
    rs_s7_tx_get_detect_state,
    S7Transaction
);
export_tx_set_detect_state!(
    rs_s7_tx_set_detect_state,
    S7Transaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_s7_probing_parser(
    _flow: *const Flow,
    _direction: u8,
    input: *const u8,
    input_len: u32,
    _rdir: *mut u8
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return unsafe { ALPROTO_S7 };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_s7_state_new() -> *mut std::os::raw::c_void {
    let state = S7State::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_s7_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<S7State> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_s7_state_tx_free(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) {
    let state = cast_pointer!(state, S7State);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_s7_parse_request(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
    }

    let state = cast_pointer!(state, S7State);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_s7_parse_response(
    _flow: *const Flow,
    state: *mut std::os::raw::c_void,
    pstate: *mut std::os::raw::c_void,
    input: *const u8,
    input_len: u32,
    _data: *const std::os::raw::c_void,
    _flags: u8,
) -> i32 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, S7State);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_response(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_s7_state_get_tx(
    state: *mut std::os::raw::c_void,
    tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, S7State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_s7_state_get_tx_count(
    state: *mut std::os::raw::c_void,
) -> u64 {
    let state = cast_pointer!(state, S7State);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_s7_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_s7_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void,
    _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, S7Transaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_s7_tx_get_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, S7Transaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_s7_tx_set_logged(
    _state: *mut std::os::raw::c_void,
    tx: *mut std::os::raw::c_void,
    logged: u32,
) {
    let tx = cast_pointer!(tx, S7Transaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_s7_state_get_events(
    tx: *mut std::os::raw::c_void
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, S7Transaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_s7_state_get_event_info(
    _event_name: *const std::os::raw::c_char,
    _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_s7_state_get_event_info_by_id(_event_id: std::os::raw::c_int,
                                                         _event_name: *mut *const std::os::raw::c_char,
                                                         _event_type: *mut core::AppLayerEventType
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_s7_state_get_tx_iterator(
    _ipproto: u8,
    _alproto: AppProto,
    state: *mut std::os::raw::c_void,
    min_tx_id: u64,
    _max_tx_id: u64,
    istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, S7State);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"s7\0";

#[no_mangle]
pub unsafe extern "C" fn rs_s7_register_parser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: rs_s7_probing_parser,
        probe_tc: rs_s7_probing_parser,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_s7_state_new,
        state_free: rs_s7_state_free,
        tx_free: rs_s7_state_tx_free,
        parse_ts: rs_s7_parse_request,
        parse_tc: rs_s7_parse_response,
        get_tx_count: rs_s7_state_get_tx_count,
        get_tx: rs_s7_state_get_tx,
        tx_get_comp_st: rs_s7_state_progress_completion_status,
        tx_get_progress: rs_s7_tx_get_alstate_progress,
        get_tx_logged: Some(rs_s7_tx_get_logged),
        set_tx_logged: Some(rs_s7_tx_set_logged),
        get_de_state: rs_s7_tx_get_detect_state,
        set_de_state: rs_s7_tx_set_detect_state,
        get_events: Some(rs_s7_state_get_events),
        get_eventinfo: Some(rs_s7_state_get_event_info),
        get_eventinfo_byid : Some(rs_s7_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_s7_state_get_tx_iterator),
        get_tx_detect_flags: None,
        set_tx_detect_flags: None,
        flags: 0,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_S7 = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust s7 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for S7.");
    }
}
