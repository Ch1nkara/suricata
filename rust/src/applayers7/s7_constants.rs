#[derive(Debug)]
pub enum S7Functions {
    // startup parameters
    ReadVar,
    UnknownFunction,
}

impl S7Functions {
    pub fn to_str(&self) -> &str {
        match self {
            S7Functions::ReadVar => "Read Variable",
            S7Functions::UnknownFunction => "Unknown function",
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub function: S7Functions,
}