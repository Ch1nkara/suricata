use super::s8::S8Transaction;
use crate::debug_validate_bug_on;
use lazy_static::lazy_static;
use regex::Regex;
use std::ffi::CStr;
use std::ops::{Range, RangeInclusive};
use std::os::raw::{c_char, c_void};
use std::str::FromStr;

#[derive(Debug, PartialEq, Default)]
pub struct DetectS8Rust {
    function: Option<u8>,
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_s8_inspect(tx: &S8Transaction, modbus: &DetectS8Rust) -> u8 {
    SCLogNotice!("in inspector for detection");
    return 1;
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn rs_s8_parse(c_arg: *const c_char) -> *mut c_void {
    SCLogNotice!("in s8_parse");
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

fn parse_function(func_str: &str) -> Result<DetectS8Rust, ()> {

    let mut modbus: DetectS8Rust = Default::default();
    Ok(modbus)
}

fn parse_unit_id(unit_str: &str) -> Result<DetectS8Rust, ()> {
    let mut modbus: DetectS8Rust = Default::default();
    Ok(modbus)
}