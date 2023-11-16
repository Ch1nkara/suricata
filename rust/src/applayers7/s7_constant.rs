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