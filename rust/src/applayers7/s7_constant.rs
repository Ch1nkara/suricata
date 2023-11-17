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

pub const INIT_FRAME_LENGTH: usize = 22;
pub const INIT_TPKT_VERSION: u8 = 0x03; /* TPKT version used  in S7 protocol */
pub const INIT_TPKT_RESERVED: u8 = 0x00; /* TPKT reserved byte used  in S7 protocol */
pub const INIT_TPKT_INIT_LENGTH_1: u8 = 0x00; /* frame length in connect steps */
pub const INIT_TPKT_INIT_LENGTH_2: u8 = 0x16; /* frame length in connect steps */
pub const COTP_CONNECT_REQUEST: u8 = 0xE0; /* COTP initialisation codes */
pub const COTP_CONNECT_CONFIRM: u8 = 0xD0; /* COTP initialisation codes */
pub const S7_PROTOCOLE_ID: u8 = 0x32; /* S7 protocol id code */

#[derive(Debug)]
pub struct S7Comm {
    pub function: Option<S7Function>,
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum S7Function {
    ReadVariable = 0x04,
    WriteVariable = 0x05,
}

impl std::str::FromStr for S7Function {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "read" => Ok(S7Function::ReadVariable),
            "write" => Ok(S7Function::WriteVariable),
            _ => Err(format!("'{}' is not a valid value for S7Function", input_string)),
        }
    }
}

//TODO unit tests
