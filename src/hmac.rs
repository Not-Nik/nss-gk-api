// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]

use crate::err::IntoResult;
use crate::hash::HashAlgorithm;
use crate::p11;
use crate::p11::PK11Origin;
use crate::p11::PK11_CreateContextBySymKey;
use crate::p11::PK11_DigestFinal;
use crate::p11::PK11_DigestOp;
use crate::p11::PK11_ImportSymKey;
use crate::p11::Slot;
use crate::SECItemBorrowed;
use crate::{Error, Result};
use pkcs11_bindings::CKA_SIGN;
use std::convert::TryFrom;
use std::ptr;

//
// Constants
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlgorithm {
    HMAC_SHA2_256,
    HMAC_SHA2_384,
    HMAC_SHA2_512,
}

impl HmacAlgorithm {
    pub fn len(&self) -> usize {
        let hash_alg: HashAlgorithm = (*self).into();
        hash_alg.len()
    }
}

impl Into<p11::CK_MECHANISM_TYPE> for HmacAlgorithm {
    fn into(self) -> p11::CK_MECHANISM_TYPE {
        match self {
            HmacAlgorithm::HMAC_SHA2_256 => p11::CKM_SHA256_HMAC.into(),
            HmacAlgorithm::HMAC_SHA2_384 => p11::CKM_SHA384_HMAC.into(),
            HmacAlgorithm::HMAC_SHA2_512 => p11::CKM_SHA512_HMAC.into(),
        }
    }
}

impl Into<HashAlgorithm> for HmacAlgorithm {
    fn into(self) -> HashAlgorithm {
        match self {
            HmacAlgorithm::HMAC_SHA2_256 => HashAlgorithm::SHA2_256,
            HmacAlgorithm::HMAC_SHA2_384 => HashAlgorithm::SHA2_384,
            HmacAlgorithm::HMAC_SHA2_512 => HashAlgorithm::SHA2_512,
        }
    }
}

pub fn hmac(alg: HmacAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    crate::init();

    let data_len = match u32::try_from(data.len()) {
        Ok(data_len) => data_len,
        _ => return Err(Error::InternalError),
    };

    let slot = Slot::internal()?;
    let sym_key = unsafe {
        PK11_ImportSymKey(
            *slot,
            alg.into(),
            PK11Origin::PK11_OriginUnwrap,
            CKA_SIGN,
            SECItemBorrowed::wrap(key).as_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };
    let param = SECItemBorrowed::make_empty();
    let context = unsafe {
        PK11_CreateContextBySymKey(alg.into(), CKA_SIGN, *sym_key, param.as_ref()).into_result()?
    };
    unsafe { PK11_DigestOp(*context, data.as_ptr(), data_len).into_result()? };
    let expected_len = alg.len();
    let mut digest = vec![0u8; expected_len];
    let mut digest_len = 0u32;
    unsafe {
        PK11_DigestFinal(
            *context,
            digest.as_mut_ptr(),
            &mut digest_len,
            digest.len() as u32,
        )
        .into_result()?
    }
    assert_eq!(digest_len as usize, expected_len);
    Ok(digest)
}
