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

/* Parsing the suricata rule when keyword is s7 */
fn parse_rule(rule_str: &str) -> Result<S7CommSignature, ()> {
    //SCLogNotice!("rule_str: {}", rule_str);
    let mut words: Vec<&str> = rule_str.split_whitespace().rev().collect();

    let rule_type = words.pop().unwrap_or("EOF");

    let mut word_to_parse = words.pop().unwrap_or("EOF");
    let mut whitelist_mode = false;
    if word_to_parse.starts_with('!') {
        whitelist_mode = true;
        /* Support for old rule format by allowing no spaces
         * between "!" and the first word */
        if word_to_parse.len() > 1 {
            word_to_parse = &word_to_parse[1..];
        } else {
            word_to_parse = words.pop().unwrap_or("EOF");
        }
    }

    let mut rosctr_list = Vec::new();
    let mut function_list = Vec::new();
    let mut item_list = Vec::new();
    let mut function = S7Function::CpuServices;
    loop {
        /* Support for old rule format by skipping "and" keyword */
        if word_to_parse == "and" {
            word_to_parse = words.pop().unwrap_or("EOF");
        }
        /* exit condition: words vec is empty*/
        if word_to_parse == "EOF" {
            break;
        }
        match rule_type {
            "rosctr" => rosctr_list = parse_rosctr_word(word_to_parse, rosctr_list)?,
            "function" => function_list = parse_function_word(word_to_parse, function_list)?,
            "read" => {
                    item_list = parse_item_word(word_to_parse, item_list)?;
                    function = S7Function::ReadVariable
                }
            "write" => {
                item_list = parse_item_word(word_to_parse, item_list)?;
                function = S7Function::WriteVariable
            }
            _ => {
                SCLogError!("Unknown rule type: {}", rule_type);
                return Err(())
            }
        }
        word_to_parse = words.pop().unwrap_or("EOF");
    }

    let mut s7_sign: S7CommSignature = Default::default();
    s7_sign.whitelist_mode = whitelist_mode;

    /* Building the signature. There are 3 types of signature: rosctr, function or read/write
     * Checking which list is not empty to deduce the type of signature and building it */
    if ! rosctr_list.is_empty() {
        /* signature type rosctr */
        s7_sign.header = Some(S7HeaderSignature {rosctr: rosctr_list});
    } else if ! function_list.is_empty() {
        /* signature type function */
        s7_sign.parameter = Some(S7ParameterSignature {function: function_list, item: None});
    } else if ! item_list.is_empty() {
        /* signature type read/write */
        s7_sign.parameter = Some(S7ParameterSignature {function: vec![function], item: Some(item_list)});
    }
    SCLogNotice!("signature: {:?}", s7_sign); 
    Ok(s7_sign)
}

fn parse_rosctr_word(word_to_parse: &str, mut rosctr_list: Vec<S7Rosctr>) -> Result<Vec<S7Rosctr>, ()> {
    match S7Rosctr::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => rosctr_list.push(result),
        Err(_) => {
            SCLogError!("Failed to parse as a S7Rosctr value: {}", word_to_parse);
            return Err(())
        }
    }
    return Ok(rosctr_list);
}

fn parse_function_word(word_to_parse: &str, mut function_list: Vec<S7Function>) -> Result<Vec<S7Function>, ()> {
    match S7Function::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => function_list.push(result),
        Err(_) => {
            SCLogError!("Failed to parse as a S7Function value: {}", word_to_parse);
            return Err(())
        }
    }
    return Ok(function_list);
}

fn parse_item_word(word_to_parse: &str, mut item_list: Vec<S7Item>) -> Result<Vec<S7Item>, ()> {
    match S7Item::from_str(word_to_parse) {
        Ok(result) => item_list.push(result),
        Err(_) => {
            SCLogError!("Failed to parse as a S7Item value: {}", word_to_parse);
            return Err(())
        }
    }
    return Ok(item_list);
}

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
/*
 *

 * In whitelist mode, for each non-empty field of the signature, the field of 
 * the request must be in the vector of the corresponding field of the signature. 
 * Otherwise 1 is returned (alert is raised). 
 *
 * In non-whitelist mode, for each non-empty field of the signature, 1 is 
 * returned if the field of the request is in the Vec of the corresponding field
 * of the signature */
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &S7Transaction, s7_sign: &S7CommSignature) -> u8 {
    SCLogNotice!("inspecting transaction: \n{:?} \nagainst signature: \n{:?}", tx, s7_sign);
    /* In the transaction, only the request is compared to the signature  */
    let tx_request: &S7Comm;
    match &tx.request {
        Some(tx_r) => tx_request = tx_r,
        _ => {
            SCLogError!("Error, tx.request is NONE, no match");
            return 0
        }
    }
    /* Do not inspect if response in not None since inspection was already made
     * during the request */
     match &tx.response {
        None => {},
        _ => {
            SCLogNotice!("inspection result: no match (response found)");
            return 0
        }
     }

    /* Signature type rosctr, check if the tx rosctr is in the signature */
    let field_in_vec = header_check(tx_request, s7_sign);
    if field_in_vec {
        SCLogNotice!("inspection result: {} (header check)", field_in_vec ^ s7_sign.whitelist_mode);
        return (field_in_vec ^ s7_sign.whitelist_mode) as u8;
    }

    /* Next, signature type function and read/write match in the parameter_check function*/
    let (field_in_vec, cant_compare) = parameter_check(tx_request, s7_sign);

    /* Handle case when signature type is read/write but tx function is not read/write
     * In such case, by design, we return "no match" */
    if cant_compare {
        SCLogNotice!("inspection result: no match (cant compare)");
        return 0
    }

    SCLogNotice!("inspection result: {} (parameter check)", field_in_vec ^ s7_sign.whitelist_mode);
    return (field_in_vec ^ s7_sign.whitelist_mode) as u8;
    /* XOR explanation: 
     * in whitelist mod, match (= return 1) if (! field_in_vec) otherwise do not match (=return 0)
     * in normal mod (! whitelist), match if field_in_vec is true otherwise do not match. 
     * This can be sumurized with a xor */ 
}

fn header_check(tx_req: &S7Comm, s7_sign: &S7CommSignature) -> bool {
    return match &s7_sign.header {
        Some(hdr_sign) => hdr_sign.rosctr.contains(&tx_req.header.rosctr),
        _ => false
    }
}

fn parameter_check(tx_req: &S7Comm, s7_sign: &S7CommSignature) -> (bool, bool) {
    let param_sign;
    match &s7_sign.parameter {
        Some(result) => param_sign = result,
        _ =>  return (false, false)
    }
    let tx_param;
    match &tx_req.parameter {
        Some(result) => tx_param = result,
        _ =>  return (false, false)
    }
    let item_sign;
    match &param_sign.item {
        Some(result) => item_sign = result,
        /* If there are no items in the signature, we are in a signature type function, 
         * so we just check if the tx function is in the signature */
        _ => return (param_sign.function.contains(&tx_param.function), false)
    }
    /* Beyond this point, signature type can only be read/write */ 
    let tx_item;
    match &tx_param.item {
        Some(result) => tx_item = result,
        /* If the signature contains item but the request do not, return "no match"
         * by setting cant_compare to true (whatever whitelist_mode is) because
         * it means that the rule is s7:read[...] or s7:write[...], which imply 
         * "only look for match in read or write frames and ignore other frames" */
        _ => return (false, true)
    }
    /* Before checking for item inclusion, check that the function is correct */
    match param_sign.function.first() {
        Some(result) => if tx_param.function != *result {
                return (false, true)
            },
        _ => return (false, false)
    }
    /* last check, if tx_item vector is included in item_sign vector */
    for element in tx_item {
        if ! item_sign.contains(&element) {
            return (false, false)
        }
    }
    return (true, false)
}

/// Intermediary function between the C code and the parsing functions.
#[no_mangle]
pub unsafe extern "C" fn rs_s7_parse(c_arg: *const c_char) -> *mut c_void {
    if c_arg.is_null() {
        return std::ptr::null_mut();
    }
    if let Ok(arg) = CStr::from_ptr(c_arg).to_str() {
        match parse_rule(arg)
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
        let _ = Box::from_raw(ptr as *mut S7CommSignature);
    }
}

//TODO unit tests
//verify line length 
