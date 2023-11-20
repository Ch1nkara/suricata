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
    number::complete::be_u16,
    IResult,
};
use std;

use super::s7_constant::{S7Function, S7Comm, S7Rosctr, S7Parameter, 
    S7TransportSize, S7Item};
use super::s7_constant::{
    COTP_HEADER_LENGTH, TPKT_HEADER_LENGTH, S7_HEADER_LENGTH
};

//TODO change to s7_parse_message
pub fn s7_parse_request(input: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in request parser, input: {:x?}", input);
    let mut s7_comm = S7Comm {
        header: None,
        parameter: None,
        data: None,
    };
    
    let (input, _) = take(TPKT_HEADER_LENGTH
        + COTP_HEADER_LENGTH)(input)?;

    let (input, header_slice) = take(S7_HEADER_LENGTH)(input)?;
    match S7Rosctr::from_u8(header_slice[1]) {
        Ok(result) => s7_comm.header = Some(result),
        Err(msg) => return Ok((&[], s7_comm))
    }

    let param_length: u16 = be_u16(&header_slice[6..8])?.1;

    let (input, parameter_slice) = take(param_length.max(14))(input)?;
    let mut parameter: S7Parameter;
    match S7Function::from_u8(parameter_slice[0]) {
        Ok(result) => parameter = S7Parameter {
                function: Some(result),
                item: None,
            },
        Err(msg) => return Ok((&[], s7_comm))
    }
    match S7TransportSize::from_u8(parameter_slice[5]) {
        Ok(result) => parameter.item = Some(S7Item {
                transport_size: result,
                length: be_u16(&parameter_slice[6..8])?.1,
                db_number: be_u16(&parameter_slice[8..10])?.1,
                //TODO implement with bits::take
                byte_address: 0_u32,
                bit_address: 0_u8,
            }),
        Err(msg) => return Ok((&[], s7_comm))
    }
    s7_comm.parameter = Some(parameter);
    return Ok((&[], s7_comm))
}

pub fn s7_parse_response(i: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in response parser, input: {:x?}", i);
    return Ok((&[], S7Comm {
        header: None,
        parameter: None,
        data: None,
    }))
}

//TODO Unit tests
//verify line length 
