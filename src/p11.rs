// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::aead::AeadAlgorithms;
use crate::err::{secstatus_to_res, Error, Result};
use crate::p11::PK11ObjectType::PK11_TypePrivKey;
use crate::p8::PKCS8Encoded;
use crate::util::SECItemMut;

use pkcs11_bindings::CKA_EC_POINT;
use pkcs11_bindings::CKA_VALUE;

use std::convert::{TryFrom, TryInto};
use std::os::raw::{c_int, c_uint};
use std::ptr;

#[must_use]
pub fn hex_with_len(buf: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let buf = buf.as_ref();
    let mut ret = String::with_capacity(10 + buf.len() * 2);
    write!(&mut ret, "[{}]: ", buf.len()).unwrap();
    for b in buf {
        write!(&mut ret, "{:02x}", b).unwrap();
    }
    ret
}

#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::unreadable_literal)]
#[allow(unknown_lints, clippy::borrow_as_ptr)]
mod nss_p11 {
    use crate::nss_prelude::*;
    use crate::prtypes::*;
    include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));
}

use crate::{init, prtypes::*, IntoResult, SECItem, SECItemBorrowed, PR_FALSE};
pub use nss_p11::*;

// Shadow these bindgen created values to correct their type.
pub const SHA256_LENGTH: usize = nss_p11::SHA256_LENGTH as usize;
pub const AES_BLOCK_SIZE: usize = nss_p11::AES_BLOCK_SIZE as usize;

scoped_ptr!(Certificate, CERTCertificate, CERT_DestroyCertificate);
scoped_ptr!(CertList, CERTCertList, CERT_DestroyCertList);

scoped_ptr!(
    SubjectPublicKeyInfo,
    CERTSubjectPublicKeyInfo,
    SECKEY_DestroySubjectPublicKeyInfo
);

scoped_ptr!(PublicKey, SECKEYPublicKey, SECKEY_DestroyPublicKey);
impl_clone!(PublicKey, SECKEY_CopyPublicKey);

impl PublicKey {
    /// Get the HPKE serialization of the public key.
    ///
    /// # Errors
    /// When the key cannot be exported, which can be because the type is not supported.
    /// # Panics
    /// When keys are too large to fit in `c_uint/usize`.  So only on programming error.
    pub fn key_data(&self) -> Result<Vec<u8>> {
        let mut buf = vec![0; 100];
        let mut len: c_uint = 0;
        secstatus_to_res(unsafe {
            PK11_HPKE_Serialize(
                **self,
                buf.as_mut_ptr(),
                &mut len,
                c_uint::try_from(buf.len()).unwrap(),
            )
        })?;
        buf.truncate(usize::try_from(len).unwrap());
        Ok(buf)
    }

    pub fn key_data_alt(&self) -> Result<Vec<u8>> {
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            PK11_ReadRawAttribute(
                PK11ObjectType::PK11_TypePubKey,
                (**self).cast(),
                CKA_EC_POINT,
                key_item.as_mut(),
            )
        })?;
        Ok(key_item.as_slice().to_owned())
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        mechanism: std::os::raw::c_ulong,
    ) -> Result<bool> {
        init();
        unsafe {
            let mut data_to_sign = SECItemBorrowed::wrap(&data);
            let mut signature = SECItemBorrowed::wrap(&signature);

            let rv = crate::p11::PK11_VerifyWithMechanism(
                self.as_mut().unwrap(),
                mechanism.into(),
                std::ptr::null_mut(),
                signature.as_mut(),
                data_to_sign.as_mut(),
                std::ptr::null_mut(),
            );

            match rv {
                0 => Ok(true),
                _ => Ok(false),
            }
        }
    }

    pub fn verify_ecdsa(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify(data, signature, crate::p11::CKM_ECDSA.into())
    }

    pub fn verify_eddsa(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        self.verify(data, signature, crate::p11::CKM_EDDSA.into())
    }
}

impl PKCS8Encoded for PublicKey {
    fn import_pkcs8(spki: &[u8]) -> Result<PublicKey> {
        init();
        let mut spki_item = SECItemBorrowed::wrap(&spki);
        let spki_item_ptr = spki_item.as_mut();
        let slot = Slot::internal()?;
        unsafe {
            let spki = SECKEY_DecodeDERSubjectPublicKeyInfo(spki_item_ptr)
                .into_result()
                .unwrap();
            let pk: PublicKey = crate::p11::SECKEY_ExtractPublicKey(spki.as_mut().unwrap())
                .into_result()
                .unwrap();

            let handle = PK11_ImportPublicKey(*slot, *pk, PR_FALSE);
            if handle == pkcs11_bindings::CK_INVALID_HANDLE {
                return Err(Error::InvalidInput);
            }

            Ok(pk)
        }
    }

    fn export_pkcs8(&self) -> Result<Vec<u8>> {
        init();
        let mut key_item = SECItemMut::make_empty();
        unsafe {
            PK11_ReadRawAttribute(PK11_TypePrivKey, self.cast(), CKA_VALUE, key_item.as_mut())
        };
        Ok(key_item.as_slice().to_owned())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PublicKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque PublicKey")
        }
    }
}

scoped_ptr!(PrivateKey, SECKEYPrivateKey, SECKEY_DestroyPrivateKey);
impl_clone!(PrivateKey, SECKEY_CopyPrivateKey);

impl PrivateKey {
    /// Get the bits of the private key.
    ///
    /// # Errors
    /// When the key cannot be exported, which can be because the type is not supported
    /// or because the key data cannot be extracted from the PKCS#11 module.
    /// # Panics
    /// When the values are too large to fit.  So never.
    pub fn key_data(&self) -> Result<Vec<u8>> {
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            PK11_ReadRawAttribute(
                PK11ObjectType::PK11_TypePrivKey,
                (**self).cast(),
                CKA_VALUE,
                key_item.as_mut(),
            )
        })?;
        Ok(key_item.as_slice().to_owned())
    }

    pub fn sign(&self, data: &[u8], mechanism: std::os::raw::c_ulong) -> Result<Vec<u8>> {
        init();
        let data_signature = vec![0u8; 0x40];

        let mut data_to_sign = SECItemBorrowed::wrap(&data);
        let mut signature = SECItemBorrowed::wrap(&data_signature);
        unsafe {
            secstatus_to_res(crate::p11::PK11_SignWithMechanism(
                self.as_mut().unwrap(),
                mechanism,
                std::ptr::null_mut(),
                signature.as_mut(),
                data_to_sign.as_mut(),
            ))
            .expect("Signature has failed");

            let signature = signature.as_slice().to_vec();
            Ok(signature)
        }
    }

    pub fn sign_ecdsa(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data, crate::p11::CKM_ECDSA.into())
    }

    pub fn sign_eddsa(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data, crate::p11::CKM_EDDSA.into())
    }
}

impl PKCS8Encoded for PrivateKey {
    fn import_pkcs8(pki: &[u8]) -> Result<PrivateKey> {
        init();

        // Get the PKCS11 slot
        let slot = Slot::internal()?;
        let mut der_pki = SECItemBorrowed::wrap(&pki);
        let der_pki_ptr: *mut SECItem = der_pki.as_mut();

        // Create a pointer for the private key
        let mut pk_ptr = ptr::null_mut();

        unsafe {
            secstatus_to_res(PK11_ImportDERPrivateKeyInfoAndReturnKey(
                *slot,
                der_pki_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                KU_ALL,
                &mut pk_ptr,
                ptr::null_mut(),
            ))
            .expect("PKCS8 encoded key import has failed");

            let sk = PrivateKey::from_ptr(pk_ptr)?;
            Ok(sk)
        }
    }

    fn export_pkcs8(&self) -> Result<Vec<u8>> {
        init();
        unsafe {
            let sk: crate::ScopedSECItem = PK11_ExportDERPrivateKeyInfo(**self, ptr::null_mut())
                .into_result()
                .unwrap();
            return Ok(sk.into_vec());
        }
    }
}

impl TryInto<PublicKey> for PrivateKey {
    type Error = crate::Error;

    fn try_into(self) -> std::result::Result<PublicKey, Self::Error> {
        init();
        unsafe {
            let pk = crate::p11::SECKEY_ConvertToPublicKey(*self).into_result()?;
            Ok(pk)
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PrivateKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque PrivateKey")
        }
    }
}

scoped_ptr!(Slot, PK11SlotInfo, PK11_FreeSlot);

impl Slot {
    pub fn internal() -> Result<Self> {
        unsafe { Slot::from_ptr(PK11_GetInternalSlot()) }
    }
}

// Note: PK11SymKey is internally reference counted
scoped_ptr!(SymKey, PK11SymKey, PK11_FreeSymKey);
impl_clone!(SymKey, PK11_ReferenceSymKey);

impl SymKey {
    pub fn import(key: &[u8], algorithm: AeadAlgorithms) -> Result<SymKey> {
        let slot = Slot::internal().map_err(|_| crate::Error::InternalError)?;

        let key_item = SECItemBorrowed::wrap(key);
        let key_item_ptr = key_item.as_ref() as *const _ as *mut _;

        let ptr = unsafe {
            PK11_ImportSymKey(
                *slot,
                algorithm.into(),
                PK11Origin::PK11_OriginUnwrap,
                CK_ATTRIBUTE_TYPE::from(CKA_ENCRYPT | CKA_DECRYPT),
                key_item_ptr,
                std::ptr::null_mut(),
            )
        };
        unsafe { SymKey::from_ptr(ptr) }
    }

    /// You really don't want to use this.
    ///
    /// # Errors
    /// Internal errors in case of failures in NSS.
    pub fn key_data(&self) -> Result<&[u8]> {
        secstatus_to_res(unsafe { PK11_ExtractKeyValue(**self) })?;

        let key_item = unsafe { PK11_GetKeyData(**self) };
        // This is accessing a value attached to the key, so we can treat this as a borrow.
        match unsafe { key_item.as_mut() } {
            None => Err(Error::InternalError),
            Some(key) => Ok(unsafe { std::slice::from_raw_parts(key.data, key.len as usize) }),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        self.key_data()
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "SymKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque SymKey")
        }
    }
}

unsafe fn destroy_pk11_context(ctxt: *mut PK11Context) {
    PK11_DestroyContext(ctxt, PRBool::from(true));
}
scoped_ptr!(Context, PK11Context, destroy_pk11_context);

/// Generate a randomized buffer.
/// # Panics
/// When `size` is too large or NSS fails.
#[must_use]
pub fn random(size: usize) -> Vec<u8> {
    let mut buf = vec![0; size];
    secstatus_to_res(unsafe {
        PK11_GenerateRandom(buf.as_mut_ptr(), c_int::try_from(buf.len()).unwrap())
    })
    .unwrap();
    buf
}

impl_into_result!(SECOidData);

#[cfg(test)]
mod test {
    use super::random;
    use test_fixture::fixture_init;

    #[test]
    fn randomness() {
        fixture_init();
        // If this ever fails, there is either a bug, or it's time to buy a lottery ticket.
        assert_ne!(random(16), random(16));
    }
}
