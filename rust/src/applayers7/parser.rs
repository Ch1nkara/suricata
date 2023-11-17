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

pub fn s7_parse_request(i: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in request parser, input: {:x?}", i);
    let (i, _headers) = take(17_usize)(i)?;
    let (_i, function) = take(1_usize)(i)?;
    SCLogNotice!("function: {:x?}", function);
    return match function {
        [0x04u8] => Ok((&[], S7Comm {function: Some(S7Function::ReadVariable)})),
        [0x05u8] => Ok((&[], S7Comm {function: Some(S7Function::WriteVariable)})),
        _ => Ok((&[], S7Comm {function: None})),
    };
}

pub fn s7_parse_response(i: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in response parser, input: {:x?}", i);
    Ok((&[], S7Comm {function: None}))
}

//TODO Unit tests
