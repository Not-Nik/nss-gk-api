// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::der;
use crate::err::{IntoResult, Result};
use crate::init;

use crate::p11::PK11_GenerateKeyPair;
use crate::p11::PK11_PubDeriveWithKDF;
use crate::p11::Slot;

use crate::PrivateKey;
use crate::PublicKey;
use crate::SECItem;
use crate::SECItemBorrowed;

use pkcs11_bindings::CKM_EC_EDWARDS_KEY_PAIR_GEN;
use pkcs11_bindings::CKM_EC_KEY_PAIR_GEN;
use pkcs11_bindings::CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
use pkcs11_bindings::CK_FALSE;

use std::ptr;

//
// Constants
//

// Object identifiers in DER tag-length-value form
pub const OID_EC_PUBLIC_KEY_BYTES: &[u8] = &[
    /* RFC 5480 (id-ecPublicKey) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];
pub const OID_SECP256R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp256r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
pub const OID_SECP384R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp384r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x34,
];
pub const OID_SECP521R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp521r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x35,
];

pub const OID_ED25519_BYTES: &[u8] = &[/* RFC 8410 (id-ed25519) */ 0x2b, 0x65, 0x70];
pub const OID_RS256_BYTES: &[u8] = &[
    /* RFC 4055 (sha256WithRSAEncryption) */
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

pub const OID_X25519_BYTES: &[u8] = &[
    /* https://tools.ietf.org/html/draft-josefsson-pkix-newcurves-01
     * 1.3.6.1.4.1.11591.15.1 */
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
];

pub fn object_id(val: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(der::MAX_TAG_AND_LENGTH_BYTES + val.len());
    der::write_tag_and_length(&mut out, der::TAG_OBJECT_ID, val.len())?;
    out.extend_from_slice(val);
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
}

impl EcCurve {
    fn to_oid(&self) -> Vec<u8> {
        match self {
            EcCurve::X25519 => OID_X25519_BYTES.to_vec(),
            EcCurve::Ed25519 => OID_ED25519_BYTES.to_vec(),
            EcCurve::P256 => OID_SECP256R1_BYTES.to_vec(),
            EcCurve::P384 => OID_SECP384R1_BYTES.to_vec(),
            EcCurve::P521 => OID_SECP521R1_BYTES.to_vec(),
        }
    }
}

impl Into<pkcs11_bindings::CK_MECHANISM_TYPE> for EcCurve {
    fn into(self) -> pkcs11_bindings::CK_MECHANISM_TYPE {
        match self {
            EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKM_EC_KEY_PAIR_GEN.into(),
            EcCurve::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN.into(),
            EcCurve::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN.into(),
        }
    }
}

pub type EcdhPublicKey = PublicKey;
pub type EcdhPrivateKey = PrivateKey;

pub struct EcdhKeypair {
    pub public: EcdhPublicKey,
    pub private: EcdhPrivateKey,
}

impl EcdhKeypair {
    pub fn new(public: EcdhPublicKey, private: EcdhPrivateKey) -> Self {
        EcdhKeypair { public, private }
    }

    pub fn generate(curve: EcCurve) -> Result<EcdhKeypair> {
        init();

        // Get the OID for the Curve
        let curve_oid = curve.to_oid();
        let oid_bytes = object_id(&curve_oid)?;
        let mut oid = SECItemBorrowed::wrap(&oid_bytes);
        let oid_ptr: *mut SECItem = oid.as_mut();

        // Get the Mechanism based on the Curve and its use
        let ckm = curve.into();

        // Get the PKCS11 slot
        let slot = Slot::internal()?;

        // Create a pointer for the public key
        let mut pk_ptr = ptr::null_mut();

        // https://github.com/mozilla/nss-gk-api/issues/1
        unsafe {
            let sk = PK11_GenerateKeyPair(
                *slot,
                ckm,
                oid_ptr.cast(),
                &mut pk_ptr,
                CK_FALSE.into(),
                CK_FALSE.into(),
                ptr::null_mut(),
            )
            .into_result()?;

            let pk = EcdhPublicKey::from_ptr(pk_ptr)?;

            let kp = EcdhKeypair {
                public: pk,
                private: sk,
            };

            Ok(kp)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ecdh(EcCurve);

impl Ecdh {
    pub fn new(&self, curve: EcCurve) -> Self {
        Self(curve)
    }
}

//
// Curve functions
//

pub fn ecdh(sk: PrivateKey, pk: PublicKey) -> Result<Vec<u8>> {
    init();
    let sym_key = unsafe {
        PK11_PubDeriveWithKDF(
            sk.cast(),
            pk.cast(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            pkcs11_bindings::CKM_ECDH1_DERIVE,
            pkcs11_bindings::CKM_SHA512_HMAC,
            pkcs11_bindings::CKA_SIGN,
            0,
            pkcs11_bindings::CKD_NULL,
            ptr::null_mut(),
            ptr::null_mut(),
        )
        .into_result()?
    };

    let key = sym_key.key_data().unwrap();
    Ok(key.to_vec())
}
