// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::Result;

pub trait PKCS8Encoded {
    fn import_pkcs8(pki: &[u8]) -> Result<Self>
    where
        Self: Sized;
    fn export_pkcs8(&self) -> Result<Vec<u8>>;
}
