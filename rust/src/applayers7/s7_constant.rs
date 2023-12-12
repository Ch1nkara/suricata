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

/* Frame length during the connection step */
pub const INIT_FRAME_LENGTH: usize = 22;

pub const TPKT_HEADER_LENGTH: usize = 4;
/* TPKT version used  in S7 protocol */
pub const INIT_TPKT_VERSION: u8 = 0x03; 
/* TPKT reserved byte used  in S7 protocol */
pub const INIT_TPKT_RESERVED: u8 = 0x00; 
/* frame length in connect steps */
pub const INIT_TPKT_INIT_LENGTH_1: u8 = 0x00; 
/* frame length in connect steps */
pub const INIT_TPKT_INIT_LENGTH_2: u8 = 0x16;


pub const COTP_HEADER_LENGTH: usize = 3;
/* COTP initialisation bytes (client and server) */
pub const COTP_CONNECT_REQUEST: u8 = 0xE0; 
pub const COTP_CONNECT_CONFIRM: u8 = 0xD0;

pub const S7_PROTOCOLE_ID: u8 = 0x32;
pub const S7_ADDR_OFFSET: usize = 5;
pub const S7_BYTE_ADDR_LENGTH: usize = 16;
pub const S7_BIT_ADDR_LENGTH: usize = 3;

#[derive(Debug)]
pub struct S7Comm {
    pub header: S7Header,
    pub parameter: Option<S7Parameter>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct S7Header {
    pub rosctr: S7Rosctr,
    pub param_length: u16,
    pub data_length: u16,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7Rosctr {
    JobRequest,
    Ack,
    AckData,
    Userdata,
}


#[derive(Debug)]
pub struct S7Parameter {
    pub function: S7Function,
    pub item: Option<Vec<S7Item>>,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7Function {
    CpuServices,
    ReadVariable,
    WriteVariable,
    RequestDownload,
    DownloadBlock,
    DownloadEnded,
    StartUpload,
    Upload,
    EndUpload,
    PlcControl,
    PlcStop,
    SetupCommunication,
}

#[derive(Debug, PartialEq)]
pub struct S7Item {
    pub transport_size: S7TransportSize,
    pub length: u16,
    pub db_number: u16,
    pub area: u8,
    pub byte_address: u16,
    pub bit_address: u16,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7TransportSize {
    Bit,
    Byte,
    Char,
    Word,
}

impl S7Rosctr {
    pub fn from_u8(input_u8: u8) -> Result<Self, String> {
        match input_u8 {
            0x01_u8 => Ok(S7Rosctr::JobRequest),
            0x02_u8 => Ok(S7Rosctr::Ack),
            0x03_u8 => Ok(S7Rosctr::AckData),
            0x07_u8 => Ok(S7Rosctr::Userdata),
            _ => Err(format!("'{}' cannot be converted with S7Rosctr::from_u8", input_u8)),
        }
    }
}

impl S7Function {
    pub fn from_u8(input_u8: u8) -> Result<Self, String> {
        match input_u8 {
            0x00_u8 => Ok(S7Function::CpuServices),
            0x04_u8 => Ok(S7Function::ReadVariable),
            0x05_u8 => Ok(S7Function::WriteVariable),       
            0x1A_u8 => Ok(S7Function::RequestDownload),
            0x1B_u8 => Ok(S7Function::DownloadBlock),
            0x1C_u8 => Ok(S7Function::DownloadEnded),       
            0x1D_u8 => Ok(S7Function::StartUpload),
            0x1E_u8 => Ok(S7Function::Upload),
            0x1F_u8 => Ok(S7Function::EndUpload),
            0x28_u8 => Ok(S7Function::PlcControl),       
            0x29_u8 => Ok(S7Function::PlcStop),
            0xF0_u8 => Ok(S7Function::SetupCommunication),
            _ => Err(format!("'{}' cannot be converted with S7Function::from_u8", input_u8)),
        }
    }
}

impl std::str::FromStr for S7Item {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {

        let mut parts: Vec<&str> = input_string.split('_').rev().collect();

        if parts.len() != 4 {
            return Err(format!("Error parsing '{}' with S7Item::from_str: wrong length", input_string));
        }
        let db_number;
        //SCLogNotice!("S7Item::from_str, last element", err)
        match parts.pop().unwrap_or("EOF").parse() {
            Ok(result) => db_number = result,
            _ => return Err(format!("Error parsing '{}' with S7Item::from_str: first element", input_string))
        }
        let transport_size;
        match S7TransportSize::from_str(parts.pop().unwrap_or("EOF")) {
            Ok(result) => transport_size = result,
            _ => return Err(format!("Error parsing '{}' with S7Item::from_str: second element", input_string))
        }

        let address: Vec<&str> = parts.pop().unwrap_or("EOF").split('.').collect();
        if address.len() != 2 {
            return Err(format!("Error parsing '{}' with S7Item::from_str: third element", input_string));
        }
        let byte_address;
        match address[0].parse() {
            Ok(result) => byte_address = result,
            _ => return Err(format!("Error parsing '{}' with S7Item::from_str: third element", input_string))
        }
        let bit_address;
        match address[1].parse() {
            Ok(result) => bit_address = result,
            _ => return Err(format!("Error parsing '{}' with S7Item::from_str: third element", input_string))
        }

        let length;
        match parts.pop().unwrap_or("EOF").parse() {
            Ok(result) => length = result,
            _ => return Err(format!("Error parsing '{}' with S7Item::from_str: fourth element", input_string))
        }
        Ok(S7Item {
            transport_size,
            length,
            db_number,
            area: 0x84_u8,
            byte_address,
            bit_address,
        })
    }
}

impl std::str::FromStr for S7TransportSize {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "1" => Ok(S7TransportSize::Bit),
            "2" => Ok(S7TransportSize::Byte),
            "3" => Ok(S7TransportSize::Char),
            "4" => Ok(S7TransportSize::Word),
            _ => Err(format!("'{}' cannot be converted with S7TransportSize::from_str", input_string)),
        }
    }
}
impl S7TransportSize {
    pub fn from_u8(input_u8: u8) -> Result<Self, String> {
        match input_u8 {
            0x01_u8 => Ok(S7TransportSize::Bit),
            0x02_u8 => Ok(S7TransportSize::Byte),
            0x03_u8 => Ok(S7TransportSize::Char),
            0x04_u8 => Ok(S7TransportSize::Word),
            _ => Err(format!("'{}' cannot be converted with S7Function::from_u8", input_u8)),
        }
    }
}

#[derive(Debug)]
pub struct S7CommSignature {
    pub sign_type: S7SignatureType,
    pub whitelist_mode: bool,
    pub rosctr: Option<Vec<S7Rosctr>>,
    pub function: Option<Vec<S7Function>>,
    pub item: Option<Vec<S7Item>>,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7SignatureType {
    Rosctr,
    Function,
    ReadWrite,
}
impl std::str::FromStr for S7SignatureType {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "rosctr" => Ok(S7SignatureType::Rosctr),
            "function" => Ok(S7SignatureType::Function),
            "read" => Ok(S7SignatureType::ReadWrite),
            "write" => Ok(S7SignatureType::ReadWrite),
            _ => Err(format!("'{}' cannot be converted with S7SignatureType::from_str", input_string)),
        }
    }
}

//TODO unit tests
//verify line length 
