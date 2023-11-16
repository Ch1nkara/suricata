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
 * with s7 PDU: S7_Header + Parameter + Data */
pub fn s7_parse_message(input: &[u8]) -> IResult<&[u8], S7Comm> {
    SCLogDebug!("starting parser: {:x?}", input);
    /* Parsing the header part */
    let (remainder, header) = s7_parse_header(input)?;

    /* Parsing the parameter part */
    let mut parameter: Option<S7Parameter> = None;
    let (remainder, parameter_slice) = take(header.param_length)(remainder)?;
    if header.param_length != 0 {       
        let (_, param) = s7_parse_parameter(parameter_slice)?;
        parameter = Some(param);
    }

    /*  Parsing the data part */
    let (remainder, data_slice) = take(header.data_length)(remainder)?;

    /* Checking that we have no unexpected remainder */
    if ! remainder.is_empty() {
        SCLogError!("Unexpected remainder while parsing 
                s7 PDU: {:x?}", remainder);
        return Err(Error(make_error(input, ErrorKind::Eof)))
    }

    return Ok((&[], S7Comm {
        header,
        parameter,
        data: data_slice.into()
    }))
}

fn s7_parse_header(input: &[u8]) -> IResult<&[u8], S7Header> {
    /* Get rid of the tpkt and cotp headers*/
    let (s7_pdu, _) = take(TPKT_HEADER_LENGTH
        + COTP_HEADER_LENGTH)(input)?;   

    let (remainder, proto_id) = be_u8(s7_pdu)?;
    if proto_id != S7_PROTOCOLE_ID {
        SCLogError!("Not a s7 pdu: {:x?}", s7_pdu);
        return Err(Error(make_error(input, ErrorKind::Verify)))
    }
    let (remainder, rosctr_value) = be_u8(remainder)?;
    let rosctr;
    match S7Rosctr::from_u8(rosctr_value) {
        Ok(result) => rosctr = result,
        Err(msg) => {
            SCLogError!("Error parsing S7Rosctr: {}", msg);
            return Err(Error(make_error(s7_pdu, ErrorKind::Verify)))
        }
    }
    /* not parsed: reserved bytes (2bytes) and PDU ref (2bytes) */
    let (remainder, _) = take(4_usize)(remainder)?;
    let (remainder, param_length) = be_u16(remainder)?;
    let (remainder, data_length) = be_u16(remainder)?;

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
            SCLogError!("Error parsing S7Function: {}", msg);
            return Err(Error(make_error(parameter_slice, ErrorKind::Verify)))
        }
    }
    /* If S7Function is ReadVar or WriteVar and the remainder has more than 1 
     * byte, it means that the parameter slice contains items. We want to parse 
     * them */
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
        /* not parsed:  
         * - Variable spec (1byte)
         * - Length of following address spec (1byte)
         * - Syntax Id (1byte) */
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
                SCLogError!("Error parsing S7TransportSize: {}", msg);
                return Err(Error(make_error(param_slice, ErrorKind::Verify)))
            }
        }

        /* Parse the address (3bytes) which is not intuitive: 
         * .....AAA (first byte) 
         * AAAAAAAA (2nd byte) 
         * AAAAABBB (third byte)
         * with A being the byte_address bits 
         * B being the bit_address bits */
        let (addr_rem, byte_address);
        match parse_bits((address, S7_ADDR_OFFSET), S7_BYTE_ADDR_LENGTH) {
            Ok((rem, result)) => (addr_rem, byte_address) = (rem, result),
            Err(err) => {
                SCLogError!("Error parsing byte adress: {}", err);
                return Err(Error(make_error(param_slice, ErrorKind::Eof)))
            }
        }
        let bit_address: u16;
        match parse_bits(addr_rem, S7_BIT_ADDR_LENGTH) {
            Ok((_, result)) => bit_address = result,
            Err(err) => {
                SCLogError!("Error parsing bit adress: {}", err);
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
        SCLogError!("Unexpected remainder while parsing 
                items: {:x?}", remainder);
        return Err(Error(make_error(param_slice, ErrorKind::Eof)))
    }
    return Ok((&[], item_list))
}

fn parse_bits(input: (&[u8], usize), count: usize) 
        -> IResult<(&[u8], usize), u16> {
    return nom7::bits::complete::take(count)(input);
}

#[cfg(test)]
mod test {
    use super::s7_parse_message;
    use super::super::s7_constant::{S7Comm, S7Header, S7Parameter, S7Item,
            S7Rosctr::*, S7Function::*, S7TransportSize::*};
    use nom7::{ error::{make_error, ErrorKind}, Err::Error};
    #[test]
    fn test_parse_message() {
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 
                0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
                0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: JobRequest, 
                    param_length: 8,
                    data_length: 0 },
                parameter: Some(S7Parameter{
                    function: SetupCommunication, 
                    item: None}),
                data: vec![],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x1b, 0x02, 0xf0, 0x80, 
                0x32, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
                0x00, 0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: AckData, 
                    param_length: 8,
                    data_length: 0 },
                parameter: Some(S7Parameter{
                    function: SetupCommunication, 
                    item: None}),
                data: vec![],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 
                0x32, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0e, 0x00, 0x00, 
                0x04, 0x01, 0x12, 0x0a, 0x10, 0x04, 0x00, 0x09, 0x00, 0x01, 
                0x84, 0x00, 0x00, 0x30]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: JobRequest, 
                    param_length: 14,
                    data_length: 0 },
                parameter: Some(S7Parameter{
                    function: ReadVariable, 
                    item: Some(vec![S7Item {
                        transport_size: Word,
                        length: 9,
                        db_number: 1,
                        area: 132,
                        byte_address: 6,
                        bit_address: 0,}])}),
                data: vec![],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x22, 0x02, 0xf0, 0x80, 
                0x32, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x0d, 
                0x00, 0x00, 0x04, 0x01, 0xff, 0x04, 0x00, 0x48, 0x00, 0x00, 
                0x80, 0x71, 0x40, 0x2a, 0x11, 0x56, 0x00]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: AckData, 
                    param_length: 2,
                    data_length: 13 },
                parameter: Some(S7Parameter{
                    function: ReadVariable, 
                    item: None}),
                data: vec![0xff, 0x04, 0x00, 0x48, 0x00, 0x00, 0x80, 0x71, 
                    0x40, 0x2a, 0x11, 0x56, 0x00],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x24, 0x02, 0xf0, 0x80, 
                0x32, 0x01, 0x00, 0x00, 0x0f, 0x04, 0x00, 0x1a, 0x00, 0x0a, 
                0x05, 0x02, 0x12, 0x0a, 0x10, 0x01, 0x00, 0x01, 0x00, 0x00, 
                0x83, 0x00, 0x00, 0x00, 0x12, 0x0a, 0x10, 0x02, 0x00, 0x09, 
                0x00, 0x01, 0x84, 0x00, 0x00, 0x30, 0x00, 0x04, 0x00, 0x08, 
                0x3b, 0x00, 0x04, 0x00, 0x08, 0x3c]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: JobRequest, 
                    param_length: 26,
                    data_length: 10 },
                parameter: Some(S7Parameter{
                    function: WriteVariable, 
                    item: Some(vec![
                        S7Item {
                            transport_size: Bit,
                            length: 1,
                            db_number: 0,
                            area: 131,
                            byte_address: 0,
                            bit_address: 0,}, 
                        S7Item {
                            transport_size: Byte,
                            length: 9,
                            db_number: 1,
                            area: 132,
                            byte_address: 6,
                            bit_address: 0,}])}),
                data: vec![0x00, 0x04, 0x00, 0x08, 0x3b, 0x00, 0x04, 0x00, 
                    0x08, 0x3c],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x16, 0x02, 0xf0, 0x80, 
                0x32, 0x03, 0x00, 0x00, 0x0f, 0x07, 0x00, 0x02, 0x00, 0x01, 
                0x00, 0x00, 0x05, 0x02, 0xff]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: AckData, 
                    param_length: 2,
                    data_length: 1 },
                parameter: Some(S7Parameter{
                    function: WriteVariable, 
                    item: None}),
                data: vec![0xff],
            }))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 
                0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 
                0x19, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0]),
            Err(Error(make_error( 
                vec![25, 0, 0, 1, 0, 1, 1, 224].as_slice(), 
                ErrorKind::Verify )))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x16, 0x02, 0xf0, 0x80, 
                0x32, 0x03, 0x00, 0x00, 0x0f, 0x07, 0x00, 0x02, 0x00, 0x01, 
                0x00, 0x00, 0x05, 0x02, 0x00, 0xff]),
            Err(Error(make_error( 
                vec![3, 0, 0, 22, 2, 240, 128, 50, 3, 0, 0, 15, 7, 0, 2, 0, 1, 
                    0, 0, 5, 2, 0, 255].as_slice(), 
                ErrorKind::Eof )))
        );
        assert_eq!(
            s7_parse_message(&vec![0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80, 
                0x32, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0e, 0x00, 0x00, 
                0x04, 0x01, 0x12, 0x0a, 0x10, 0x03, 0xff, 0xff, 0xff, 0xff, 
                0xff, 0xff, 0xff, 0xff]),
            Ok((vec![].as_slice(), S7Comm {
                header: S7Header {
                    rosctr: JobRequest, 
                    param_length: 14,
                    data_length: 0 },
                parameter: Some(S7Parameter{
                    function: ReadVariable, 
                    item: Some(vec![S7Item {
                        transport_size: Char,
                        length: 65535,
                        db_number: 65535,
                        area: 255,
                        byte_address: 65535,
                        bit_address: 7,}])}),
                data: vec![],
            }))
        );
    }
}
