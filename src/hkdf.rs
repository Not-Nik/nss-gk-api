// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]

use crate::Error;
use crate::SECItem;
use crate::SECItemType;

use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_int;
use std::os::raw::c_uint;
// use crate::init;
// use crate::p11::{PK11Origin, PK11_CreateContextBySymKey, PK11_ImportSymKey, Slot};
use crate::p11;
// use crate::p11::ParamItem;
use crate::p11::SymKey;
use crate::ssl::CK_OBJECT_HANDLE;
// use crate::Error;
// use crate::SECItemBorrowed;
use crate::p11::CKA_DERIVE;
use crate::p11::CKF_HKDF_SALT_DATA;
use crate::p11::CKF_HKDF_SALT_NULL;
use crate::p11::CKM_HKDF_DATA;
use crate::p11::CKM_HKDF_DERIVE;
use crate::p11::CK_BBOOL;
use crate::p11::CK_INVALID_HANDLE;
use crate::p11::CK_MECHANISM_TYPE;
// use crate::p11::CK_ULONG;
use pkcs11_bindings::CK_ULONG;
use std::convert::TryFrom;
// use std::ptr;
use std::ptr::null_mut;

pub enum HkdfAlgorithm {
    HKDF_SHA2_256,
    HKDF_SHA2_384,
    HKDF_SHA2_512,
}

fn hkdf_alg_to_p11_prf_hash_mechanism(alg: &HkdfAlgorithm) -> p11::CK_MECHANISM_TYPE {
    match alg {
        HkdfAlgorithm::HKDF_SHA2_256 => p11::CKM_SHA256.into(),
        HkdfAlgorithm::HKDF_SHA2_384 => p11::CKM_SHA384.into(),
        HkdfAlgorithm::HKDF_SHA2_512 => p11::CKM_SHA512.into(),
    }
}

pub(crate) struct ParamItem<'a, T: 'a> {
    item: SECItem,
    marker: PhantomData<&'a T>,
}

impl<'a, T: Sized + 'a> ParamItem<'a, T> {
    pub fn new(v: &'a mut T) -> Self {
        let item = SECItem {
            type_: SECItemType::siBuffer,
            data: (v as *mut T).cast::<u8>(),
            len: c_uint::try_from(mem::size_of::<T>()).unwrap(),
        };
        Self {
            item,
            marker: PhantomData::default(),
        }
    }

    pub fn ptr(&mut self) -> *mut SECItem {
        std::ptr::addr_of_mut!(self.item)
    }
}

pub fn extract(alg: &HkdfAlgorithm, salt: &[u8], ikm: &SymKey) -> Result<Vec<u8>, Error> {
    let salt_type = if salt.is_empty() {
        CKF_HKDF_SALT_NULL
    } else {
        CKF_HKDF_SALT_DATA
    };
    let mut params = p11::CK_HKDF_PARAMS {
        bExtract: CK_BBOOL::from(true),
        bExpand: CK_BBOOL::from(false),
        prfHashMechanism: hkdf_alg_to_p11_prf_hash_mechanism(&alg),
        ulSaltType: CK_ULONG::from(salt_type),
        pSalt: salt.as_ptr() as *mut _, // const-cast = bad API
        ulSaltLen: CK_ULONG::try_from(salt.len()).unwrap(),
        hSaltKey: CK_OBJECT_HANDLE::from(CK_INVALID_HANDLE),
        pInfo: null_mut(),
        ulInfoLen: 0,
    };
    let mut params_item = ParamItem::new(&mut params);
    let ptr = unsafe {
        p11::PK11_Derive(
            **ikm,
            CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
            params_item.ptr(),
            CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
            CK_MECHANISM_TYPE::from(CKA_DERIVE),
            0,
        )
    };

    let prk = unsafe { SymKey::from_ptr(ptr) }?;
    let r = Vec::from(prk.as_bytes()?);
    // trace!(
    //     "HKDF extract: salt={} ikm={} prk={}",
    //     hex::encode(salt),
    //     hex::encode(ikm.key_data()?),
    //     hex::encode(prk.key_data()?),
    // );
    Ok(r)
}

fn expand_params(alg: &HkdfAlgorithm, info: &[u8]) -> p11::CK_HKDF_PARAMS {
    p11::CK_HKDF_PARAMS {
        bExtract: CK_BBOOL::from(false),
        bExpand: CK_BBOOL::from(true),
        prfHashMechanism: hkdf_alg_to_p11_prf_hash_mechanism(&alg),
        ulSaltType: CK_ULONG::from(CKF_HKDF_SALT_NULL),
        pSalt: null_mut(),
        ulSaltLen: 0,
        hSaltKey: CK_OBJECT_HANDLE::from(CK_INVALID_HANDLE),
        pInfo: info.as_ptr() as *mut _, // const-cast = bad API
        ulInfoLen: CK_ULONG::try_from(info.len()).unwrap(),
    }
}

pub fn expand(
    alg: &HkdfAlgorithm,
    prk: &SymKey,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut params = expand_params(&alg, info);
    let mut params_item = ParamItem::new(&mut params);
    let ptr = unsafe {
        p11::PK11_Derive(
            **prk,
            CK_MECHANISM_TYPE::from(CKM_HKDF_DATA),
            params_item.ptr(),
            CK_MECHANISM_TYPE::from(CKM_HKDF_DERIVE),
            CK_MECHANISM_TYPE::from(CKA_DERIVE),
            c_int::try_from(len).unwrap(),
        )
    };
    let k = unsafe { SymKey::from_ptr(ptr) }?;
    let r = Vec::from(k.as_bytes()?);
    // trace!(
    //     "HKDF expand_data: prk={} info={} okm={}",
    //     hex::encode(prk.key_data()?),
    //     hex::encode(info),
    //     hex::encode(&r),
    // );
    Ok(r)
}
