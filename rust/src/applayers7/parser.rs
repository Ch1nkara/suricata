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
    IResult, error::{make_error, ErrorKind, ParseError},
    Err::Error
};
use std;

use super::s7_constant::*;

//TODO change to s7_parse_message
pub fn s7_parse_request(input: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogNotice!("in request parser, input: {:x?}", input);
    
    let (s7_pdu, _) = take(TPKT_HEADER_LENGTH
        + COTP_HEADER_LENGTH)(input)?;    

    /* Protect againt index out of range */
    if !(s7_pdu.len() > S7_ROSCTR_POS) {
        return Err(Error(make_error(s7_pdu, ErrorKind::Eof)))
    }

    /* Parsing S7 PDU : Header - Parameter - Data*/
    let mut s7_comm;
    /* Parsing the header part */
    let remainder: &[u8];
    let s7_header: S7Header;
    match S7Rosctr::from_u8(s7_pdu[S7_ROSCTR_POS]) {
        Ok(S7Rosctr::AckData) => (remainder, s7_header) = s7_parse_header(s7_pdu, S7_LONG_HEADER_LENGTH)?,
        Ok(result) => (remainder, s7_header) = s7_parse_header(s7_pdu, S7_HEADER_LENGTH)?,
        Err(_msg) => return Err(Error(make_error(s7_pdu, ErrorKind::Verify)))
    }
    s7_comm = S7Comm {
        header: s7_header,
        parameter: None,
        data: None,
    };
    SCLogNotice!("Header parser: {:x?}", s7_comm);

    /* Parsing the parameter part */
    let (remainder, parameter_slice) = take(s7_comm.header.param_length)(remainder)?;
    /* Protect againt index out of range */
    if !(parameter_slice.len() > 0) {
        return Ok((&[], s7_comm))
    }
    let param_function: S7Function;
    let mut param_item: Option<Vec<S7Item>> = None;
    match S7Function::from_u8(parameter_slice[0]) {
        Ok(result) => param_function = result,
        Err(_) => return Ok((&[], s7_comm))
    }
    if (param_function == S7Function::ReadVariable) || 
        (param_function == S7Function::WriteVariable) {
            let (_, item) = s7_parse_item(parameter_slice)?;
            param_item = Some(item)
    }
    s7_comm.parameter = Some(S7Parameter {
        function: param_function,
        item: param_item
    });
    SCLogNotice!("Param parser: {:x?}", s7_comm);

    /*  Parsing the data part */
    if s7_comm.header.data_length != 0 {
        let (_, data_slice) = take(s7_comm.header.data_length)(remainder)?;
        s7_comm.data = Some(data_slice.into());
        SCLogNotice!("Data parser: {:x?}", s7_comm);
    }

    if ! remainder.is_empty() {
        SCLogNotice!("REMAINDER NOT EMPTY: {:x?}", remainder);
        return Err(Error(make_error(s7_pdu, ErrorKind::Eof)))
    }
    return Ok((&[], s7_comm))    
}

pub fn s7_parse_response(i: &[u8]) -> IResult<&[u8], S7Comm> {
    //SCLogNotice!("in response parser, input: {:x?}", i);
    return Ok((&[], S7Comm {
        header: S7Header {
            rosctr: S7Rosctr::Ack,
            param_length: 0,
            data_length: 0
        },
        parameter: None,
        data: None,
    }))
}

fn s7_parse_header(s7_pdu: &[u8], header_length: usize) -> IResult<&[u8], S7Header> {
    let (remainder, header_slice) = take(header_length)(s7_pdu)?;
    let rosctr = match S7Rosctr::from_u8(header_slice[S7_ROSCTR_POS]) {
        Ok(result) => result,
        Err(_msg) => return Err(Error(make_error(s7_pdu, ErrorKind::Verify))) 
    };
    let param_length: u16 = be_u16(&header_slice[S7_PARAM_LENGTH_POS..S7_PARAM_LENGTH_POS + 2])?.1;
    let data_length: u16 = be_u16(&header_slice[S7_DATA_LENGTH_POS..S7_DATA_LENGTH_POS + 2])?.1;

    return Ok((remainder, S7Header {
            rosctr,
            param_length,
            data_length
        }
    ))
}

fn s7_parse_item(param_slice: &[u8]) -> IResult<&[u8], Vec<S7Item>> {
    let mut item_slice: &[u8];
    let (remainder, _function) = take(1_usize)(param_slice)?;
    let (mut remainder, nb_item) = take(1_usize)(remainder)?;
    SCLogNotice!("nb_item: {:x?}, remainder: {:x?}", nb_item, remainder);

    let mut item_list: Vec<S7Item> = Vec::new();
    for nbitem in 0..nb_item[0] {
        (remainder, item_slice) = take(S7_ITEM_LENGTH)(remainder)?;
        if item_slice[S7_LEN_OF_FOLL_ADD_SPEC_POS] != S7_LEN_OF_FOLL_ADD_SPEC {
            /* Unexpected frame length, return error */
            return Err(Error(make_error(param_slice, ErrorKind::Verify)))  
        }
        if item_slice[S7_ITEM_AREA_POS] != S7_AREA_DATA_BLOCKS {
            /* Unexpected area, return error */
            return Err(Error(make_error(param_slice, ErrorKind::Verify)))  
        }
        let transport_size;
        match S7TransportSize::from_u8(item_slice[S7_TRANSPORT_SIZE_POS]) {
            Ok(result) => transport_size = result,
            Err(_msg) => return Err(Error(make_error(param_slice, ErrorKind::Verify)))
        }
        let address = &item_slice[S7_ITEM_ADDR_POS..S7_ITEM_ADDR_POS + 2];
//        let byte_addr: u16 = match nom7::bits::complete::take::<&[u8], u16, usize, ParseError<(&[u8], usize)>>(16_usize)((address, 5_usize)) {
//            Ok(((remainder, offset), result)) => result,
//            _ => 0
//        };
        //let ((addr_rem, offset), byte_addr) = nom7::bits::complete::take(16_usize)((address, 5_usize))?;
        //let (addr_rem, byte_addr) = nom7::bits::complete::take(16_usize)(addr_rem)?;
        //let (addr_rem, bit_addr) = nom7::bits::complete::take(3_usize)(addr_rem)?;

        item_list.push(S7Item {
            transport_size,
            length: be_u16(&item_slice[S7_ITEM_LEN_POS..S7_ITEM_LEN_POS + 2])?.1,
            db_number: be_u16(&item_slice[S7_ITEM_DB_POS..S7_ITEM_DB_POS + 2])?.1,
            area: S7_AREA_DATA_BLOCKS,
            byte_address: 0,
            bit_address: 0,
//            byte_address: be_u16(byte_addr)?.1,
//            bit_address: be_u8(bit_addr)?.1,
        })
    }   
    return Ok((&[], item_list))
}

//    let (_input, parameter_slice) = take(param_length.max(14))(input)?;
//    let mut parameter: S7Parameter;
//    match S7Function::from_u8(parameter_slice[0]) {
//        Ok(result) => parameter = S7Parameter {
//                function: Some(result),
//                item: None,
//            },
//        Err(_msg) => return Ok((&[], s7_comm))
//    }
//    match S7TransportSize::from_u8(parameter_slice[5]) {
//        Ok(result) => parameter.item = Some(S7Item {
//                transport_size: result,
//                length: be_u16(&parameter_slice[6..8])?.1,
//                db_number: be_u16(&parameter_slice[8..10])?.1,
//                //TODO implement with bits::take
//                byte_address: 0_u32,
//                bit_address: 0_u8,
//            }),
//        Err(_msg) => return Ok((&[], s7_comm))
//    }

//TODO Unit tests
//verify line length 
