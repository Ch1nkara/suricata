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

use super::s7::S7Transaction;
use super::s7_constant::{S7Comm, S7Function};
use std::{
    ffi::CStr,
    os::raw::{c_char, c_void},
    str::FromStr
};

#[derive(Debug, Default)]
pub struct DetectS7Signature {
    function: Option<S7Function>,
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &S7Transaction, s7: &DetectS7Signature) -> u8 {
    SCLogNotice!("inspecting, transaction: {:?}", tx);
    let tx_request: &S7Comm;
    match &tx.request {
        Some(tx_r) => tx_request = tx_r,
        _ => {SCLogNotice!("tx.request is NONE"); return 0}
    }
    //TODO reimplement detect function
//    if tx_request.header == s7.function {
//        SCLogNotice!("ALERT");
//        return 1
//    }
    SCLogNotice!("no match");
    return 0;
}

//TODO improve by match S7Function::from_str() or something like that
fn parse_function(rule_str: &str) -> Result<DetectS7Signature, ()> {
    let mut s7: DetectS7Signature = Default::default();
    SCLogNotice!("rule_str: {}", rule_str);
    let mut words = rule_str.split_whitespace();
    match S7Function::from_str(words.next().unwrap_or("")) {
        Ok(s7_function) => s7.function = Some(s7_function),
        _ => {
            SCLogNotice!("word not a function: {:?}", words.next()); 
            return Err(())
        }
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

//TODO unit tests
//verify line length 
