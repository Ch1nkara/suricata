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

use nom7::{
    bytes::streaming::take,
    IResult,
};
use std;

use super::s7_constant::{S7Function, S7Comm};
use super::s7_constant::{
    COTP_HEADER_LENGTH, TPKT_HEADER_LENGTH, S7_HEADER_LENGTH
};

pub fn s7_parse_request(input: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in request parser, input: {:x?}", input);
    
    let (input, _headers_bytes) = take(TPKT_HEADER_LENGTH
        + COTP_HEADER_LENGTH + S7_HEADER_LENGTH)(input)?;
    let (_input, function_byte) = take(1_usize)(input)?;
    SCLogNotice!("function: {:x?}", function_byte);
    return match S7Function::from_u8(function_byte[0]) {
        Ok(s7_function) => Ok((&[], S7Comm {function: Some(s7_function)})),
        _ => Ok((&[], S7Comm {function: None}))
    }
}

pub fn s7_parse_response(i: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in response parser, input: {:x?}", i);
    Ok((&[], S7Comm {function: None}))
}

//TODO Unit tests
//verify line length 
