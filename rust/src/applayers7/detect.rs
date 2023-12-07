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
use super::s7_constant::{S7Comm, S7Function, S7Item, S7CommSignature, 
    S7Rosctr, S7HeaderSignature, S7ParameterSignature};
use std::{
    ffi::CStr,
    os::raw::{c_char, c_void},
    str::FromStr
};

//TODO improve by match S7Function::from_str() or something like that
fn parse_rule(rule_str: &str, s7_signtruc: Option<S7CommSignature>) -> Result<S7CommSignature, ()> {
    SCLogNotice!("s7_signtruc: {:?}", s7_signtruc); 
    SCLogNotice!("rule_str: {}", rule_str);
    let mut words: Vec<&str> = rule_str.split_whitespace().rev().collect();

    let rule_type = words.pop().unwrap_or("EOF");
    let mut continue_parsing = true;

    let mut first_word = words.pop().unwrap_or("EOF");
    let mut whitelist_mode = false;
    if first_word.starts_with('!') {
        whitelist_mode = true;
        words.push(&first_word[1..])
    }

    let mut rosctr_list = Vec::new();
    let mut function_list = Vec::new();
    let mut item_list = Vec::new();
    let mut function = S7Function::CpuServices;
    while continue_parsing {
        let word_to_parse = words.pop().unwrap_or("EOF");
        match rule_type {
            "rosctr" => rosctr_list = parse_rosctr_word(word_to_parse, rosctr_list),
            "function" => function_list = parse_function_word(word_to_parse, function_list),
            "read" => {
                    item_list = parse_item_word(word_to_parse, item_list);
                    function = S7Function::ReadVariable
                }
            "write" => {
                item_list = parse_item_word(word_to_parse, item_list);
                function = S7Function::WriteVariable
            }
            _ => {}
        }
        if word_to_parse == "EOF" {
            continue_parsing = false;
        }
    }

    let mut s7_sign: S7CommSignature = Default::default();
    s7_sign.whitelist_mode = whitelist_mode;

    if ! rosctr_list.is_empty() {
        s7_sign.header = Some(S7HeaderSignature {rosctr: rosctr_list});
    } else if ! function_list.is_empty() {
        s7_sign.parameter = Some(S7ParameterSignature {function: function_list, item: None});
    } else if ! item_list.is_empty() {
        s7_sign.parameter = Some(S7ParameterSignature {function: vec![function], item: Some(item_list)});
    }
    SCLogNotice!("signature: {:?}", s7_sign); 
    Ok(s7_sign)
}

fn parse_rosctr_word(word_to_parse: &str, mut rosctr_list: Vec<S7Rosctr>) -> Vec<S7Rosctr> {
    match S7Rosctr::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => rosctr_list.push(result),
        _ => {}
    }
    return rosctr_list;
}

fn parse_function_word(word_to_parse: &str, mut function_list: Vec<S7Function>) -> Vec<S7Function> {
    match S7Function::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => function_list.push(result),
        _ => {}
    }
    return function_list;
}

fn parse_item_word(word_to_parse: &str, mut item_list: Vec<S7Item>) -> Vec<S7Item> {
    match S7Item::from_str(word_to_parse) {
        Ok(result) => item_list.push(result),
        _ => {}
    }
    return item_list;
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &S7Transaction, s7: &S7CommSignature) -> u8 {
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

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn rs_s7_parse(c_arg: *const c_char, s7: *mut c_void) -> *mut c_void {
    SCLogNotice!("in s7_parse");
    if c_arg.is_null() {
        SCLogNotice!("arg null");
        return std::ptr::null_mut();
    }
    //let mut s7_sign: Option<S7CommSignature> = S7CommSignature::from_ptr(s7);
    let mut s7_sign: Option<S7CommSignature> = None;
    SCLogNotice!("arg NOT null");
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_rule(arg, s7_sign)
        {
            Ok(detect) => return Box::into_raw(Box::new(detect)) as *mut c_void,
            //Ok(detect) => return s7,
            Err(_) => return std::ptr::null_mut(),
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_s7_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut S7CommSignature);
    }
}

//TODO unit tests
//verify line length 
