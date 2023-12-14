use super::s7::S7Transaction;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[derive(Debug, PartialEq, Default)]
pub struct DetectS7Rust {
    function: Option<u8>,
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &mut S7Transaction, modbus: &mut DetectS7Rust) -> u8 {
    SCLogNotice!("in inspector for detection");
    return 1;
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn rs_s7_parse(c_arg: *const c_char) -> *mut c_void {
    SCLogNotice!("in s7_parse");
    if c_arg.is_null() {
        SCLogNotice!("arg null");
        return std::ptr::null_mut();
    }
    SCLogNotice!("arg NOT null");
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_unit_id(arg)
            .or_else(|_| parse_function(arg))
        {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(()) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

fn parse_function(func_str: &str) -> Result<DetectS7Rust, ()> {

    let mut modbus: DetectS7Rust = Default::default();
    Ok(modbus)
}

fn parse_unit_id(unit_str: &str) -> Result<DetectS7Rust, ()> {
    let mut modbus: DetectS7Rust = Default::default();
    Ok(modbus)
}