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
use crate::jsonbuilder::{JsonBuilder, JsonError};
use std;

//TODO log stuff
fn log_s7(_tx: &S7Transaction, _js: &mut JsonBuilder) -> Result<(), JsonError> {
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn rs_s7_logger_log(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, S7Transaction);
    log_s7(tx, js).is_ok()
}

//TODO unit tests
//verify line length 
