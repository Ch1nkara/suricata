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
use super::s7_constant::{S7Comm, S7CommSignature, S7SignatureType};

/// Compares a transaction to a signature to determine whether the transaction
/// matches the signature. If it does, 1 is returned; otherwise 0 is returned.
/* In whitelist mode, matching means the transaction is not part of the 
 * signature. In normal, matching means the transaction is part of the 
 * signature. 
 * Only the request is inspected, and the inspection is based on the signature
 * type */
#[no_mangle]
pub extern "C" fn rs_s7_inspect(tx: &S7Transaction, s7_sign: &S7CommSignature)
         -> u8 
{
    SCLogDebug!("inspecting transaction: {:?}", tx);
    SCLogDebug!("against signature: \n{:?}", s7_sign);
    /* In the transaction, only the request is compared to the signature  */
    let tx_request = match &tx.request {
        Some(result) => result,
        _ => {
            SCLogError!("Error, tx.request is NONE, no match");
            return 0
        }
    };
    /* If the transaction has no response, we inspect the request. If it has a
     * response, it means the request has already been inspected, so we inspect
     * the reponse */
    let s7_comm = match &tx.response {
       Some(result) => result,
       None => tx_request,
    };

    let field_in_vec = match s7_sign.sign_type {
        S7SignatureType::Rosctr => is_rosctr_in_vec(s7_comm, s7_sign),
        S7SignatureType::Function => is_function_in_vec(s7_comm, s7_sign),
        S7SignatureType::ReadWrite => is_item_in_vec(s7_comm, s7_sign)
    };
    SCLogDebug!("Match result: {}", field_in_vec ^ s7_sign.whitelist_mode);
    return (field_in_vec ^ s7_sign.whitelist_mode) as u8;
    /* XOR explanation: 
     * In whitelist mode, match (= return 1) if (! field_in_vec) otherwise do
     * not match (=return 0)
     * In normal mod (! whitelist), match if field_in_vec is true otherwise do
     * not match. 
     * This can be sumurized with a xor */ 
}

fn is_rosctr_in_vec(tx_req: &S7Comm, s7_sign: &S7CommSignature) -> bool {
    return match &s7_sign.rosctr {
        Some(result) => result.contains(&tx_req.header.rosctr),
        _ => false
    }
}

fn is_function_in_vec(tx_req: &S7Comm, s7_sign: &S7CommSignature) -> bool {
    let function_vec;
    match &s7_sign.function {
        Some(result) => function_vec = result,
        _ =>  return false
    }
    let tx_function;
    match &tx_req.parameter {
        Some(result) => tx_function = &result.function,
        _ =>  return false
    }
    return function_vec.contains(tx_function)
}

fn is_item_in_vec(tx_req: &S7Comm, s7_sign: &S7CommSignature) -> bool {
    /* Check that the s7 function match with the signature*/ 
    let function_vec = match &s7_sign.function {
        Some(result) => result,
        /* Impossible case, we return whitelist mode value so that the XOR
         * returns 0 (no match) */ 
        _ =>  return s7_sign.whitelist_mode
    };
    let sign_function = match function_vec.first() {
        Some(result) => result,
        /* Impossible case, we return whitelist mode value so that the XOR
         * returns 0 (no match) */ 
        _ => return s7_sign.whitelist_mode
    };
    
    let tx_param = match &tx_req.parameter {
        Some(result) => result,
        /* Case possible if tx is not a read/write frame. Since this signature
         * type is a condition only for read/write frames, we return whitelist
         * mode value so that the XOR returns 0 (no match) */
        _ =>  return s7_sign.whitelist_mode
    };
    let tx_function = &tx_param.function;
    if tx_function != sign_function {
        /* In this case we want the inspect function to return "no match" (0),
         * so we return whitelist mode value so that the XOR returns 0 (no 
         * match) */
        return s7_sign.whitelist_mode
    }
    let tx_item = match &tx_param.item {
        Some(result) => result,
        /* Only possible for a response because the items ref are in the data
         * field. We want to return no match because this signature type is for
         * the request frame. So we return whitelist mode value so that the XOR
         * returns 0 (no match) */
        _ => return s7_sign.whitelist_mode
    };
    let sign_item = match &s7_sign.item {
        Some(result) => result,
        /* Impossible case, we return whitelist mode value so that the XOR
         * returns 0 (no match) */ 
        _ => return s7_sign.whitelist_mode
    };
    for element in tx_item {
        if ! sign_item.contains(&element) {
            return false
        }
    }
    return true
}

#[cfg(test)]
mod test {
    use super::rs_s7_inspect;
    use super::super::s7::S7Transaction;
    use super::super::s7_constant::{S7Comm, S7Header, S7Parameter, S7Item, 
        S7CommSignature, S7Rosctr::*, S7Function::*, S7TransportSize::*, 
        S7SignatureType::*};
    #[test]
    fn test_rs_s7_inspect() {
        let tx = S7Transaction::new();
        let s7_sign = S7CommSignature {
            sign_type: Rosctr,
            whitelist_mode: false,
            rosctr: Some(vec![JobRequest]),
            function: None,
            item: None,};
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);

        /* sign_type: Rosctr */
        let mut tx = S7Transaction::new();
        tx.request = Some(S7Comm {
            header: S7Header {
                    rosctr: JobRequest, 
                    param_length: 0, 
                    data_length: 0
                },
            parameter: None, 
            data: vec![]});
        let mut s7_sign = S7CommSignature {
            sign_type: Rosctr,
            whitelist_mode: true,
            rosctr: Some(vec![Ack, JobRequest, AckData]),
            function: None,
            item: None,};
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = false;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.rosctr = Some(vec![Ack, AckData]);
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = true;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        tx.response = Some(S7Comm {
            header: S7Header {
                    rosctr: AckData, 
                    param_length: 0, 
                    data_length: 0
                },
            parameter: None, 
            data: vec![]});
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = false;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.rosctr = Some(vec![Ack, JobRequest]);
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = true;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);

        /* sign_type: Function */
        let mut tx = S7Transaction::new();
        tx.request = Some(S7Comm {
            header: S7Header {
                rosctr: JobRequest, 
                param_length: 14,
                data_length: 0 },
            parameter: Some(S7Parameter{
                function: ReadVariable, 
                item: Some(vec![S7Item {
                    transport_size: Byte,
                    length: 9,
                    db_number: 1,
                    area: 132,
                    byte_address: 6,
                    bit_address: 0,}])}),
            data: vec![],});
        let mut s7_sign = S7CommSignature {
            sign_type: Function,
            whitelist_mode: true,
            rosctr: None,
            function: Some(vec![Upload, WriteVariable, ReadVariable]),
            item: None,};
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = false;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.function = Some(vec![Upload, WriteVariable]);
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.whitelist_mode = true;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        tx.response = Some(S7Comm {
            header: S7Header {
                rosctr: AckData, 
                param_length: 2,
                data_length: 13 },
            parameter: Some(S7Parameter{
                function: ReadVariable, 
                item: None}),
            data: vec![0xff, 0x04, 0x00, 0x48, 0x00, 0x00, 0x80, 0x71, 
                0x40, 0x2a, 0x11, 0x56, 0x00],});
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.whitelist_mode = false;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.function = Some(vec![Upload, WriteVariable, ReadVariable]);
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.whitelist_mode = true;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);

        /* sign_type: ReadWrite */
        let mut s7_sign = S7CommSignature {
            sign_type: ReadWrite,
            whitelist_mode: false,
            rosctr: None,
            function: Some(vec![ReadVariable]),
            item: Some(vec![
                S7Item {
                    transport_size: Bit,
                    length: 1,
                    db_number: 0,
                    area: 131,
                    byte_address: 0,
                    bit_address: 0,}, 
                S7Item {
                    transport_size: Byte,
                    length: 9,
                    db_number: 1,
                    area: 132,
                    byte_address: 6,
                    bit_address: 0}])};
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        tx.response = None;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.whitelist_mode = true;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
        s7_sign.item = Some(vec![S7Item {
            transport_size: Bit,
            length: 1,
            db_number: 0,
            area: 131,
            byte_address: 0,
            bit_address: 0,}]);
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 1);
        s7_sign.whitelist_mode = false;
        assert_eq!(rs_s7_inspect(&tx, &s7_sign), 0);
    }
}