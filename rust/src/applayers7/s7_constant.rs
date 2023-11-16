pub const INIT_FRAME_LENGTH: usize = 22;
pub const INIT_TPKT_VERSION: u8 = 0x03; /* TPKT version used  in S7 protocol */
pub const INIT_TPKT_RESERVED: u8 = 0x00; /* TPKT reserved byte used  in S7 protocol */
pub const INIT_TPKT_INIT_LENGTH_1: u8 = 0x00; /* frame length in connect steps */
pub const INIT_TPKT_INIT_LENGTH_2: u8 = 0x16; /* frame length in connect steps */
pub const COTP_CONNECT_REQUEST: u8 = 0xE0; /* COTP initialisation codes */
pub const COTP_CONNECT_CONFIRM: u8 = 0xD0; /* COTP initialisation codes */
pub const S7_PROTOCOLE_ID: u8 = 0x32; /* S7 protocol id code */

#[repr(u8)]
#[derive(Debug)]
pub enum S7Function {
    ReadVariable = 0x04,
}

impl std::str::FromStr for S7Function {
    type Err = String;
    fn from_str(input_string: &str) -> Result<Self, Self::Err> {
        match input_string {
            "read" => Ok(S7Function::ReadVariable),
            _ => Err(format!("'{}' is not a valid value for S7Function", input_string)),
        }
    }
}

//impl S7Function {
//    pub fn to_str(&self) -> &str {
//        match self {
//            S7Function::ReadVariable => "Read Variable",
//        }
//    }
//}

#[derive(Debug)]
pub struct Request {
    pub function: S7Function,
}
