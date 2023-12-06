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
    number::complete::be_u8,
    IResult, error::{make_error, ErrorKind},
    Err::Error
};
use std;

use super::s7_constant::*;

    /* Parsing the s7 frame:
     * TPKT_Header + COTP_Header + S7_Header + Parameter + Data 
     * with s7 PDU: S7_Header + Parameter + Data
    */

pub fn s7_parse_message(input: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("starting parser: {:x?}", input);
    let (remainder, header) = s7_parse_header(input)?;
    //SCLogNotice!("parsing header: {:?}", header);

    /* Parsing the parameter part */
    let mut parameter: Option<S7Parameter> = None;
    let (remainder, parameter_slice) = take(header.param_length)(remainder)?;
    if header.param_length != 0 {       
        let (_, param) = s7_parse_parameter(parameter_slice)?;
        parameter = Some(param);
    }
    //SCLogNotice!("parsing parameter: {:?}", parameter);

    /*  Parsing the data part */
    let (remainder, data_slice) = take(header.data_length)(remainder)?;
    //SCLogNotice!("parsing data: {:x?}", data_slice);

    /* Checking that we have no unexpected remainder */
    if ! remainder.is_empty() {
        SCLogNotice!("LAST REMAINDER NOT EMPTY: {:x?}", remainder);
        return Err(Error(make_error(input, ErrorKind::Eof)))
    }

    return Ok((&[], S7Comm {
        header,
        parameter,
        data: data_slice.into()
    }))
}

fn s7_parse_header(input: &[u8]) -> IResult<&[u8], S7Header> {
    let (s7_pdu, _) = take(TPKT_HEADER_LENGTH
        + COTP_HEADER_LENGTH)(input)?;   

    let (remainder, proto_id) = be_u8(s7_pdu)?;
    if proto_id != S7_PROTOCOLE_ID {
        SCLogNotice!("Not a s7 pdu: {:x?}", s7_pdu);
        return Err(Error(make_error(input, ErrorKind::Verify)))
    }
    let (remainder, rosctr_value) = be_u8(remainder)?;
    /* not parsed: reserved bytes (2bytes) and PDU ref (2bytes) */
    let (remainder, _) = take(4_usize)(remainder)?;
    let (remainder, param_length) = be_u16(remainder)?;
    let (remainder, data_length) = be_u16(remainder)?;

    let rosctr;
    match S7Rosctr::from_u8(rosctr_value) {
        Ok(result) => rosctr = result,
        Err(msg) => {
            SCLogNotice!("Error parsing S7Rosctr: {}", msg);
            return Err(Error(make_error(s7_pdu, ErrorKind::Verify)))
        }
    }

    let s7_header = S7Header {
        rosctr,
        param_length,
        data_length
    };

    if s7_header.rosctr == S7Rosctr::AckData {
        /* In AckData frame, the header contains 2 additional bytes 
         * These bytes are error codes and not parsed */
        return Ok((take(2_usize)(remainder)?.0, s7_header))
    }
    return Ok((remainder, s7_header))
}

fn s7_parse_parameter(parameter_slice: &[u8]) -> IResult<&[u8], S7Parameter> {
    let function: S7Function;
    let mut item: Option<Vec<S7Item>> = None;
    let (remainder, function_value) = be_u8(parameter_slice)?;
    match S7Function::from_u8(function_value) {
        Ok(result) => function = result,
        Err(msg) => {
            SCLogNotice!("Error parsing S7Function: {}", msg);
            return Err(Error(make_error(parameter_slice, ErrorKind::Verify)))
        }
    }
    /* If S7Function is ReadVar or WriteVar and the remainder has more than 1 byte,
     * it means that the parameter slice contains items. We want to parse them */
    if (function == S7Function::ReadVariable || 
        function == S7Function::WriteVariable) &&
        remainder.len() > 1
    {
        let (_, param_item) = s7_parse_item(parameter_slice)?;
        item = Some(param_item)
    }

    return Ok((&[], S7Parameter {
        function,
        item
    }))

}

fn s7_parse_item(param_slice: &[u8]) -> IResult<&[u8], Vec<S7Item>> {
    /* First byte is the function, already parsed */
    let (remainder, _function) = be_u8(param_slice)?;
    let (mut remainder, nb_item) = be_u8(remainder)?;

    /* Parse each item */
    let mut item_list: Vec<S7Item> = Vec::new();
    for _ in 0..nb_item {
        let transport_size_value;
        let length; let db_number;
        let area; let address;
        /* not parsed:  Variable spec (1byte)
         * Length of following address spec (1byte)
         * Syntax Id (1byte) */
        (remainder, _) = take(3_usize)(remainder)?;
        (remainder, transport_size_value) = be_u8(remainder)?;
        (remainder, length) = be_u16(remainder)?;
        (remainder, db_number) = be_u16(remainder)?;
        (remainder, area) = be_u8(remainder)?;
        (remainder, address) = take(3_usize)(remainder)?;

        let transport_size;
        match S7TransportSize::from_u8(transport_size_value) {
            Ok(result) => transport_size = result,
            Err(msg) => {
                SCLogNotice!("Error parsing S7TransportSize: {}", msg);
                return Err(Error(make_error(param_slice, ErrorKind::Verify)))
            }
        }

        /* Parse the address which is not intuitive */
        let (addr_rem, byte_address);
        match parse_bits((address, S7_ADDR_OFFSET), S7_BYTE_ADDR_LENGTH) {
            Ok((rem, result)) => (addr_rem, byte_address) = (rem, result),
            Err(err) => {
                SCLogNotice!("Error parsing byte adress: {}", err);
                return Err(Error(make_error(param_slice, ErrorKind::Eof)))
            }
        }
        let bit_address: u16;
        match parse_bits(addr_rem, S7_BIT_ADDR_LENGTH) {
            Ok((_, result)) => bit_address = result,
            Err(err) => {
                SCLogNotice!("Error parsing bit adress: {}", err);
                return Err(Error(make_error(param_slice, ErrorKind::Eof)))
            }
        }

        item_list.push(S7Item {
            transport_size,
            length,
            db_number,
            area,
            byte_address,
            bit_address,
        })
    }

    /* Checking that we have no unexpected remainder */
    if ! remainder.is_empty() {
        SCLogNotice!("PARSE ITEM REMAINDER NOT EMPTY: {:x?}", remainder);
        return Err(Error(make_error(param_slice, ErrorKind::Eof)))
    }
    return Ok((&[], item_list))
}

fn parse_bits(input: (&[u8], usize), count: usize)-> IResult<(&[u8], usize), u16> {
    return nom7::bits::complete::take(count)(input);
}

//TODO Unit tests
//verify line length 
