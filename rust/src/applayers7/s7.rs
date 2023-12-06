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

use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom7::{
    error::make_error, error::ErrorKind,
    IResult,
};
use std;
use std::{
    collections::VecDeque,
    os::raw::{c_char, c_int, c_void},
    ffi::CString
};

use super::parser;
use super::s7_constant::{S7Comm};
use super::s7_constant::{
    INIT_FRAME_LENGTH, INIT_TPKT_VERSION, INIT_TPKT_RESERVED,
    INIT_TPKT_INIT_LENGTH_1, INIT_TPKT_INIT_LENGTH_2,
    COTP_CONNECT_REQUEST, COTP_CONNECT_CONFIRM, S7_PROTOCOLE_ID,
    COTP_HEADER_LENGTH,TPKT_HEADER_LENGTH
};

static mut ALPROTO_S7: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum S7Event {}

#[derive(Debug)]
pub struct S7Transaction {
    tx_id: u64,
    pub request: Option<S7Comm>,
    pub response: Option<S7Comm>,

    tx_data: AppLayerTxData,
}

impl Default for S7Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl S7Transaction {
    pub fn new() -> S7Transaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for S7Transaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct S7State {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<S7Transaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<S7Transaction> for S7State {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&S7Transaction> {
        self.transactions.get(index)
    }
}

impl S7State {
    pub fn new() -> Self {
        Default::default()
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
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> S7Transaction {
        let mut tx = S7Transaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut S7Transaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        /* handle non s7 parasite frames such as cotp handshakes*/
        if is_malformed_s7(input) {
            return AppLayerResult::ok()
        }

        // If there was gap, check we can sync up again.
        //TODO how do we deal with gaps ?
        if self.request_gap {
            if probe(input).is_err() {
                SCLogNotice!("req_parsing DONE, gap is true");
                // The parser now needs to decide what to do as we are not in sync.
                // For this s7, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        match parser::s7_parse_message(input) {
            Ok((_rem, request)) => {
                SCLogNotice!("Parsing request ok: {:?}", request);
                let mut tx = self.new_tx();
                tx.request = Some(request);
                self.transactions.push_back(tx);
            }
            Err(nom7::Err::Incomplete(_)) => {
                SCLogNotice!("Parsing request failed: ERR Incomplete");
                // Not enough data. This parser doesn't give us a good indication
                // of how much data is missing so just ask for one more byte so the
                // parse is called as soon as more data is received.
                let needed = input.len() + 1;
                return AppLayerResult::incomplete(0_u32, needed as u32);
            }
            Err(err) => {
                SCLogNotice!("Parsing request failed: {}", err);
                return AppLayerResult::err();
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        /* handle non s7 parasite frames such as cotp handshakes*/
        if is_malformed_s7(input) {
            return AppLayerResult::ok()
        }

        //TODO how do we deal with gaps ?
        if self.response_gap {
            if probe(input).is_err() {
                SCLogNotice!("resp_parsing DONE, gap is true");
                // The parser now needs to decide what to do as we are not in sync.
                // For this s8, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }

        match parser::s7_parse_message(input) {
            Ok((_rem, response)) => {
                SCLogNotice!("Parsing response ok: {:?}", response);
                if let Some(tx) = self.find_request() {
                    tx.response = Some(response);
                    SCLogNotice!("Found response for request");
                }
            }
            Err(nom7::Err::Incomplete(_)) => {
                SCLogNotice!("Parsing response failed: ERR Incomplete");
                let needed = input.len() + 1;
                return AppLayerResult::incomplete(0_u32, needed as u32);
            }
            Err(err) => {
                SCLogNotice!("Parsing response failed: {}", err);
                return AppLayerResult::err();
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/* Probe for a s7 protocol. Since S7 is built on top of COTP,
*  tcp connection is considered using s7 protocol if :
*   - on port 102
*   - valid COTP connection on top of TCP 
* Not perfect but sufficient */
fn probe(input: &[u8]) -> IResult<&[u8], ()> {
    SCLogNotice!("in prober function");
    /* fail probe if PDU not the right size for comm setup */
    if ! input.len() == INIT_FRAME_LENGTH { 
        return Err(nom7::Err::Error(make_error(input, ErrorKind::Verify)))
    }

    let (cotp_payload, tpkt_payload) = nom7::bytes::complete::take(4_usize)(input)?;

    /* fail probe if not the proper COTP initialisation */
    if tpkt_payload != [INIT_TPKT_VERSION, 
                        INIT_TPKT_RESERVED, 
                        INIT_TPKT_INIT_LENGTH_1, 
                        INIT_TPKT_INIT_LENGTH_2] || 
       (cotp_payload[1] != COTP_CONNECT_REQUEST && cotp_payload[1] != COTP_CONNECT_CONFIRM)
    {
        return Err(nom7::Err::Error(make_error(input, ErrorKind::Verify)))
    }

    SCLogNotice!("SUCCESS");
    return Ok((&[], ()))
}

fn is_malformed_s7(input: &[u8]) -> bool{
    SCLogNotice!("malformed input: {:x?}", input);
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

// C exports. Almost only from template

/// C entry point for a probing parser.
unsafe extern "C" fn rs_s7_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_S7;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn rs_s7_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = S7State::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_s7_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut S7State));
}

unsafe extern "C" fn rs_s7_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, S7State);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_s7_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, S7State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn rs_s7_parse_response(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, S7State);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn rs_s7_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, S7State);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_s7_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, S7State);
    return state.tx_id;
}

unsafe extern "C" fn rs_s7_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, S7Transaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_s7_get_tx_data, S7Transaction);
export_state_data_get!(rs_s7_get_state_data, S7State);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"s7\0";

#[no_mangle]
pub unsafe extern "C" fn rs_s7_register_parser() {
    let default_port = CString::new("[102]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_s7_probing_parser),
        probe_tc: Some(rs_s7_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_s7_state_new,
        state_free: rs_s7_state_free,
        tx_free: rs_s7_state_tx_free,
        parse_ts: rs_s7_parse_request,
        parse_tc: rs_s7_parse_response,
        get_tx_count: rs_s7_state_get_tx_count,
        get_tx: rs_s7_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_s7_tx_get_alstate_progress,
        get_eventinfo: Some(S7Event::get_event_info),
        get_eventinfo_byid: Some(S7Event::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(applayer::state_get_tx_iterator::<S7State, S7Transaction>),
        get_tx_data: rs_s7_get_tx_data,
        get_state_data: rs_s7_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_S7 = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust s7 parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for S7.");
    }
}

//TODO unit tests
//verify line length 
