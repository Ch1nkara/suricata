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

use super::s8::S8Transaction;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

fn log_s8(tx: &S8Transaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    SCLogNotice!("into the S8 logger");
    if let Some(ref request) = tx.request {
        js.set_string("request", request)?;
    }
    if let Some(ref response) = tx.response {
        js.set_string("response", response)?;
    }
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_s8_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, S8Transaction);
    log_s8(tx, js).is_ok()
}
