/* Copyright (C) 2018 Open Information Security Foundation
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

use std;
use crate::json::*;
use super::s7::S7Transaction;
use super::s7_constant::{S7Comm, S7Parameter};

fn log_s7(tx: &S7Transaction) -> Option<Json> {
    let js = Json::object();
    js.set_integer("id", tx.tx_id);
    if let Some(req) = &tx.request {
        js.set("request", log_s7comm(req));
    }
    if let Some(resp) = &tx.response {
        js.set("response", log_s7comm(resp));
    }
    return Some(js);
}

fn log_s7comm(s7_comm: &S7Comm) -> Json {
    let js_comm = Json::object();
    let js_header = Json::object();
    js_header.set_string("rosctr", &format!("{:?}", s7_comm.header.rosctr));
    js_header.set_integer("parameter length", s7_comm.header.param_length.into());
    js_header.set_integer("data length", s7_comm.header.data_length.into());
    js_comm.set("header", js_header);
    match &s7_comm.parameter {
        Some(result) => {
            let mut js_param = Json::object();
            js_param.set_string("function", &format!("{:?}", result.function));
            js_param = add_item_if_present(&result, js_param);
            js_comm.set("parameter", js_param);
        }
        _ => {}
    }
    js_comm.set_string("data", &format!("{:?}", s7_comm.data));
    return js_comm;
}

fn add_item_if_present(param: &S7Parameter, js: Json) -> Json {
    let js_param = js;
    let item_list = match &param.item {
        Some(result) => result,
        _ => return js_param
    };
    for (index, element) in item_list.iter().enumerate(){
        let js_item = Json::object();
        js_item.set_string("transport_size", &format!("{:?}", element.transport_size));
        js_item.set_integer("length", element.length.into());
        js_item.set_integer("db_number", element.db_number.into());
        js_item.set_integer("area", element.area.into());
        js_item.set_integer("byte_address", element.byte_address.into());
        js_item.set_integer("bit_address", element.bit_address.into());
        js_param.set(&format!("item {}", index + 1), js_item);
    }
    return js_param
}

#[no_mangle]
pub extern "C" fn rs_s7_logger_log(tx: *mut std::os::raw::c_void) -> *mut JsonT {
    let tx = cast_pointer!(tx, S7Transaction);
    match log_s7(tx) {
        Some(js) => js.unwrap(),
        None => std::ptr::null_mut(),
    }
}
