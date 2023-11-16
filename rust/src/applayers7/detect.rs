use super::s7::S7Transaction;
use super::s7_constant::Request;
use super::s7_constant::S7Function;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

#[derive(Debug, Default)]
pub struct DetectS7Signature {
    function: Option<S7Function>,
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &S7Transaction, s7: &DetectS7Signature) -> u8 {
    SCLogNotice!("inspecting, transaction: {:?}", tx);
    let mut tx_request: &Request;
    match &tx.request {
        Some(tx_r) => tx_request = tx_r,
        _ => {SCLogNotice!("tx.request is NONE"); return 0}
    }
    if tx_request.function == s7.function {
        SCLogNotice!("ALERT");
        return 1
    }
    SCLogNotice!("no match");
    return 0;
}

//TODO improve by match S7Function::from_str() or something like that
fn parse_function(rule_str: &str) -> Result<DetectS7Signature, ()> {
    let mut s7: DetectS7Signature = Default::default();
    SCLogNotice!("rule_str: {}", rule_str);
    let mut words = rule_str.split_whitespace();
    match words.next() {
        Some("read") => s7.function = Some(S7Function::ReadVariable),
        Some("write") => s7.function = Some(S7Function::WriteVariable),
        _ => {SCLogNotice!("couldn't parse first word: {:?}", words.next()); return Err(())}
    }
    SCLogNotice!("signature: {:?}", s7);
    Ok(s7)
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
        match parse_function(arg)
        {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            Err(_) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_s7_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut DetectS7Signature);
    }
}
