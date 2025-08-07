// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::err::IntoResult;
use crate::init;
use crate::p11;
use crate::p11::PK11_HashBuf;
use crate::p11::SECOidTag;
use crate::{Error, Result};
use std::convert::TryFrom;

//
// Constants
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    SHA2_256,
    SHA2_384,
    SHA2_512,
}

impl HashAlgorithm {
    pub fn len(&self) -> usize {
        match self {
            HashAlgorithm::SHA2_256 => p11::SHA256_LENGTH as usize,
            HashAlgorithm::SHA2_384 => p11::SHA384_LENGTH as usize,
            HashAlgorithm::SHA2_512 => p11::SHA512_LENGTH as usize,
        }
    }
}

impl Into<SECOidTag::Type> for HashAlgorithm {
    fn into(self) -> SECOidTag::Type {
        match self {
            HashAlgorithm::SHA2_256 => SECOidTag::SEC_OID_SHA256,
            HashAlgorithm::SHA2_384 => SECOidTag::SEC_OID_SHA384,
            HashAlgorithm::SHA2_512 => SECOidTag::SEC_OID_SHA512,
        }
    }
}

//
// Hash function
//

pub fn hash(alg: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    init();

    let data_len: i32 = match i32::try_from(data.len()) {
        Ok(data_len) => data_len,
        _ => return Err(Error::InternalError),
    };
    let expected_len = alg.len();
    let mut digest = vec![0u8; expected_len];
    unsafe {
        PK11_HashBuf(alg.into(), digest.as_mut_ptr(), data.as_ptr(), data_len).into_result()?
    };
    Ok(digest)
}
