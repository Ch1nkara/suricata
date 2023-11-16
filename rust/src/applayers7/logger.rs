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
use super::s7_constant::{S7Comm, S7Parameter};
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

//TODO log stuff
fn log_s7(tx: &S7Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("s7")?;
    js.set_uint("id", tx.tx_id)?;
    if let Some(req) = &tx.request {
        js.open_object("request")?;
        log_s7comm(req, js)?;
        js.close()?;
    }
    if let Some(resp) = &tx.response {
        js.open_object("response")?;
        log_s7comm(resp, js)?;
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_s7comm(s7_comm: &S7Comm, js: &mut JsonBuilder) 
        -> Result<(), JsonError> {
    js.open_object("header")?;
    js.set_string("rosctr", &format!("{:?}", s7_comm.header.rosctr))?;
    js.set_uint("parameter length", s7_comm.header.param_length.into())?;
    js.set_uint("data length", s7_comm.header.data_length.into())?;
    js.close()?;
    match &s7_comm.parameter {
        Some(result) => {
            js.open_object("parameter")?;
            js.set_string("function", &format!("{:?}", result.function))?;
            add_item_if_present(&result, js)?;
            js.close()?;
        }
        _ => {}
    }
    js.set_string("data", &format!("{:?}", s7_comm.data))?;
    return Ok(())
}

fn add_item_if_present(param: &S7Parameter, js: &mut JsonBuilder) 
        -> Result<(), JsonError> {
    let item_list = match &param.item {
        Some(result) => result,
        _ => return Ok(())
    };
    for (index, element) in item_list.iter().enumerate(){
        js.open_object(&format!("item {}", index + 1))?;
        js.set_string(
            "transport_size", 
            &format!("{:?}", element.transport_size))?;
        js.set_uint("length", element.length.into())?;
        js.set_uint("db_number", element.db_number.into())?;
        js.set_uint("area", element.area.into())?;
        js.set_uint("byte_address", element.byte_address.into())?;
        js.set_uint("bit_address", element.bit_address.into())?;
        js.close()?;
    }
    return Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_s7_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, S7Transaction);
    log_s7(tx, js).is_ok()
}
