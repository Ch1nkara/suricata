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

pub const S7_HEADER_LENGTH: usize = 10;
pub const S7_PROTOCOLE_ID: u8 = 0x32;

#[derive(Debug)]
pub struct S7Comm {
    pub header: Option<S7Rosctr>,
    pub parameter: Option<S7Parameter>,
    pub data: Option<Vec<u8>>,
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
    pub function: Option<S7Function>,
    pub item: Option<S7Item>,
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

#[derive(Debug)]
pub struct S7Item {
    pub transport_size: S7TransportSize,
    pub length: u16,
    pub db_number: u16,
    pub byte_address: u32,
    pub bit_address: u8,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7TransportSize {
    Bit,
    Byte,
    Char,
    Word,
}

impl std::str::FromStr for S7Rosctr {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "1" => Ok(S7Rosctr::JobRequest),
            "2" => Ok(S7Rosctr::Ack),
            "3" => Ok(S7Rosctr::AckData),
            "7" => Ok(S7Rosctr::Userdata),
            _ => Err(format!("'{}' cannot be converted with S7Rosctr::from_str", input_string)),
        }
    }
}
impl S7Rosctr {
    pub fn from_u8(input_u8: u8) -> Result<Self, String> {
        match input_u8 {
            0x01u8 => Ok(S7Rosctr::JobRequest),
            0x02u8 => Ok(S7Rosctr::Ack),
            0x03u8 => Ok(S7Rosctr::AckData),
            0x07u8 => Ok(S7Rosctr::Userdata),
            _ => Err(format!("'{}' cannot be converted with S7Rosctr::from_u8", input_u8)),
        }
    }
}

impl std::str::FromStr for S7Function {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "read" => Ok(S7Function::ReadVariable),
            "write" => Ok(S7Function::WriteVariable),
            _ => Err(format!("'{}' cannot be converted with S7Function::from_str", input_string)),
        }
    }
}
impl S7Function {
    pub fn from_u8(input_u8: u8) -> Result<Self, String> {
        match input_u8 {
            0x00u8 => Ok(S7Function::CpuServices),
            0x04u8 => Ok(S7Function::ReadVariable),
            0x05u8 => Ok(S7Function::WriteVariable),       
            0x1Au8 => Ok(S7Function::RequestDownload),
            0x1Bu8 => Ok(S7Function::DownloadBlock),
            0x1Cu8 => Ok(S7Function::DownloadEnded),       
            0x1Du8 => Ok(S7Function::StartUpload),
            0x1Eu8 => Ok(S7Function::Upload),
            0x1Fu8 => Ok(S7Function::EndUpload),
            0x28u8 => Ok(S7Function::PlcControl),       
            0x29u8 => Ok(S7Function::PlcStop),
            0xF0u8 => Ok(S7Function::SetupCommunication),
            _ => Err(format!("'{}' cannot be converted with S7Function::from_u8", input_u8)),
        }
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
            0x01u8 => Ok(S7TransportSize::Bit),
            0x02u8 => Ok(S7TransportSize::Byte),
            0x03u8 => Ok(S7TransportSize::Char),
            0x04u8 => Ok(S7TransportSize::Word),
            _ => Err(format!("'{}' cannot be converted with S7Function::from_u8", input_u8)),
        }
    }
}

//TODO unit tests
//verify line length 
