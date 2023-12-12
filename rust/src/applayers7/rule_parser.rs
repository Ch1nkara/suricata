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

use super::s7_constant::{S7Function, S7Item, S7CommSignature, 
    S7Rosctr, S7SignatureType};
use std::{
    ffi::CStr,
    os::raw::{c_char, c_void},
    str::FromStr
};

/* Parsing the suricata rule to build a s7 signature. There are 3 types of 
 * signature: rosctr, function or read/write. The signature can be in whitelist
 * mode: an alert are raised if the s7 traffic is not included in the signature
 * Or, in normal mode (not whitelist), an alert is raised if the traffic is 
 * included in the signature */
 fn parse_rule(rule_str: &str) -> Result<S7CommSignature, ()> {
    //SCLogNotice!("rule_str: {}", rule_str);
    let mut words: Vec<&str> = rule_str.split_whitespace().rev().collect();

    let sign_type_str = words.pop().unwrap_or("EOF");
    let sign_type = match S7SignatureType::from_str(sign_type_str) {
        Ok(result) => result,
        Err(err) => {
            SCLogError!("Failed to parse s7 rule: {}", err);
            return Err(())
        }
    };

    let mut word_to_parse = words.pop().unwrap_or("EOF");
    let mut whitelist_mode = false;
    if word_to_parse.starts_with('!') {
        whitelist_mode = true;
        /* Support for old rule format by allowing no spaces between "!" and
         * the first word */
        if word_to_parse.len() > 1 {
            word_to_parse = &word_to_parse[1..];
        } else {
            word_to_parse = words.pop().unwrap_or("EOF");
        }
    }

    let mut rosctr_list = Vec::new();
    let mut function_list = Vec::new();
    let mut item_list = Vec::new();
    //let mut function = S7Function::CpuServices;
    loop {
        /* Support for old rule format by skipping "and" keyword */
        if word_to_parse == "and" {
            word_to_parse = words.pop().unwrap_or("EOF");
        }
        /* exit condition: words vector is empty*/
        if word_to_parse == "EOF" {
            break;
        }
        match sign_type {
            S7SignatureType::Rosctr => rosctr_list = 
                    parse_rosctr_word(word_to_parse, rosctr_list)?,
            S7SignatureType::Function => function_list = 
                    parse_function_word(word_to_parse, function_list)?,
            S7SignatureType::ReadWrite => (item_list, function_list) = 
                    parse_item_word(word_to_parse, item_list, sign_type_str)?
        }
        word_to_parse = words.pop().unwrap_or("EOF");
    }

    let mut s7_sign = S7CommSignature {
        sign_type, 
        whitelist_mode,
        rosctr: None,
        function: None,
        item: None,
    };
    match s7_sign.sign_type {
        S7SignatureType::Rosctr => s7_sign.rosctr = Some(rosctr_list),
        S7SignatureType::Function => s7_sign.function = Some(function_list),
        S7SignatureType::ReadWrite => {
            s7_sign.function = Some(function_list);
            s7_sign.item = Some(item_list)
        }
    }
    SCLogNotice!("signature: {:?}", s7_sign); 
    Ok(s7_sign)
}

fn parse_rosctr_word(word_to_parse: &str, mut rosctr_list: Vec<S7Rosctr>) 
        -> Result<Vec<S7Rosctr>, ()> 
{
    match S7Rosctr::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => rosctr_list.push(result),
        Err(err) => {
            SCLogError!("Failed to parse s7 rule: {}", err);
            return Err(())
        }
    }
    return Ok(rosctr_list);
}

fn parse_function_word(word_to_parse: &str, mut function_list: Vec<S7Function>)
        -> Result<Vec<S7Function>, ()> 
{
    match S7Function::from_u8(word_to_parse.parse().unwrap_or(255)) {
        Ok(result) => function_list.push(result),
        Err(err) => {
            SCLogError!("Failed to parse s7 rule: {}", err);
            return Err(())
        }
    }
    return Ok(function_list);
}

fn parse_item_word(word_to_parse: &str, mut item_list: Vec<S7Item>, 
        sign_type: &str) -> Result<(Vec<S7Item>, Vec<S7Function>), ()> 
{
    let function_list = match sign_type {
        "read" => vec![S7Function::ReadVariable],
        "write" => vec![S7Function::WriteVariable],
        _ => {
            SCLogError!("Unexpected s7 signature type: {}", sign_type);
            return Err(())
        }
    };
    match S7Item::from_str(word_to_parse) {
        Ok(result) => item_list.push(result),
        Err(err) => {
            SCLogError!("Failed to parse s7 rule: {}", err);
            return Err(())
        }
    }
    return Ok((item_list, function_list));
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