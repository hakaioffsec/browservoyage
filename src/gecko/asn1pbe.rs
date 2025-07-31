use aes::{
    cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, KeyIvInit},
    Aes256,
};
use asn1_rs::{DerSequence, FromDer, OctetString, Oid};
use cbc::Decryptor;
use des::TdesEde3;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::error::{BrowserVoyageError, BrowserVoyageResult};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug)]
pub enum ASN1PBE<'a> {
    NssPBE(NssPBE<'a>),
    MetaPBE(MetaPBE<'a>),
    LoginPBE(LoginPBE<'a>),
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct NssPBE<'a> {
    algo_attr: NssAlgoAttr<'a>,
    encrypted: OctetString<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct NssAlgoAttr<'a> {
    oid: Oid<'a>,
    salt_attr: NssSaltAttr<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct NssSaltAttr<'a> {
    entry_salt: OctetString<'a>,
    len: u32,
}

pub fn des3_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
    if key.len() != 24 {
        return Err(BrowserVoyageError::InvalidKeyLength(format!(
            "3DES key must be 24 bytes, got {}",
            key.len()
        )));
    }

    if iv.len() != 8 {
        return Err(BrowserVoyageError::DecryptionFailed(format!(
            "3DES IV must be 8 bytes, got {}",
            iv.len()
        )));
    }

    let mut cipher = Decryptor::<TdesEde3>::new_from_slices(key, iv).map_err(|e| {
        BrowserVoyageError::DecryptionFailed(format!("Failed to initialize 3DES cipher: {e}"))
    })?;

    let mut result = Vec::new();

    for chunk in ciphertext.chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);
        result.extend_from_slice(block.as_slice());
    }

    // Handle padding
    if let Some(&padding_length) = result.last() {
        let padding_length = padding_length as usize;
        if padding_length > 0 && padding_length <= 8 {
            result.truncate(result.len() - padding_length);
        }
    }

    Ok(result)
}

impl<'a> NssPBE<'a> {
    fn padding_zero(&self, src: &[u8], length: usize) -> Vec<u8> {
        let mut padded = src.to_vec();
        if padded.len() < length {
            let padding = length - padded.len();
            padded.extend(vec![0; padding]);
        }
        padded
    }

    pub fn decrypt(&self, global_salt: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        let (key, iv) = self.derive_key_and_iv(global_salt)?;
        des3_decrypt(&key, &iv, self.encrypted.as_cow())
    }

    fn derive_key_and_iv(&self, global_salt: &[u8]) -> BrowserVoyageResult<(Vec<u8>, Vec<u8>)> {
        let salt = &self.algo_attr.salt_attr.entry_salt;
        let mut sha1 = Sha1::new();
        sha1.update(global_salt);
        let hash_prefix = sha1.finalize();

        let mut sha1 = Sha1::new();
        let mut combined = Vec::with_capacity(hash_prefix.len() + salt.as_cow().len());
        combined.extend_from_slice(&hash_prefix);
        combined.extend_from_slice(salt.as_cow());

        sha1.update(&combined);
        let composite_hash = sha1.finalize().to_vec();

        let padded_entry_salt = self.padding_zero(salt.as_cow(), 20);

        let mut hmac_processor = HmacSha1::new_from_slice(&composite_hash).map_err(|e| {
            BrowserVoyageError::DecryptionFailed(format!("HMAC initialization failed: {e}"))
        })?;
        hmac_processor.update(&padded_entry_salt);
        let hmac_processor_result = hmac_processor.finalize().into_bytes();

        let mut padded_entry_salt_extended = padded_entry_salt.to_vec();
        padded_entry_salt_extended.extend_from_slice(salt.as_cow());
        let mut key_component1 = HmacSha1::new_from_slice(&composite_hash).map_err(|e| {
            BrowserVoyageError::DecryptionFailed(format!("HMAC initialization failed: {e}"))
        })?;
        key_component1.update(&padded_entry_salt_extended);
        let key_component1_result = key_component1.finalize().into_bytes();

        let mut hmac_with_salt = hmac_processor_result.to_vec();
        hmac_with_salt.extend_from_slice(salt.as_cow());
        let mut key_component2 = HmacSha1::new_from_slice(&composite_hash).map_err(|e| {
            BrowserVoyageError::DecryptionFailed(format!("HMAC initialization failed: {e}"))
        })?;
        key_component2.update(&hmac_with_salt);
        let key_component2_result = key_component2.finalize().into_bytes();

        let mut key = key_component1_result.to_vec();
        key.extend_from_slice(&key_component2_result);

        let iv = key.split_off(key.len() - 8);

        Ok((key, iv))
    }
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaPBE<'a> {
    algo_attr: MetaAlgoAttr<'a>,
    encrypted: OctetString<'a>,
}

fn aes_256_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    encrypted_data: &[u8],
) -> BrowserVoyageResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(BrowserVoyageError::InvalidKeyLength(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }

    if iv.len() != 16 {
        return Err(BrowserVoyageError::DecryptionFailed(format!(
            "AES IV must be 16 bytes, got {}",
            iv.len()
        )));
    }

    let mut dec = encrypted_data.to_vec();

    let result = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| {
            BrowserVoyageError::DecryptionFailed(format!(
                "Failed to initialize AES-CBC cipher: {e}"
            ))
        })?
        .decrypt_padded_mut::<Pkcs7>(&mut dec)
        .map_err(|e| {
            BrowserVoyageError::DecryptionFailed(format!("PKCS7 padding removal failed: {e}"))
        })?;

    Ok(result.to_vec())
}

impl<'a> MetaPBE<'a> {
    pub fn decrypt(&self, global_salt: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        let (key, iv) = self.derive_key_and_iv(global_salt)?;
        aes_256_cbc_decrypt(&key, &iv, self.encrypted.as_cow())
    }

    fn derive_key_and_iv(&self, global_salt: &[u8]) -> BrowserVoyageResult<(Vec<u8>, Vec<u8>)> {
        let mut sha1 = Sha1::new();
        sha1.update(global_salt);
        let password = sha1.finalize();

        let salt = &self.algo_attr.data.data.slat_attr.entry_salt;
        let key_len = self.algo_attr.data.data.slat_attr.key_size;
        let iter = self.algo_attr.data.data.slat_attr.iteration_count;

        let mut key = vec![0u8; key_len as usize];
        pbkdf2_hmac::<Sha256>(&password, salt.as_cow(), iter, &mut key);

        let mut iv = vec![4u8, 14u8];
        iv.extend_from_slice(self.algo_attr.data.iv_data.iv.as_cow());

        Ok((key.to_vec(), iv))
    }
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaAlgoAttr<'a> {
    oid: Oid<'a>,
    data: MetaData<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaData<'a> {
    data: MetaInnerData<'a>,
    iv_data: MetaIVAttr<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaInnerData<'a> {
    oid: Oid<'a>,
    slat_attr: MetaSlatAttr<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaIVAttr<'a> {
    oid: Oid<'a>,
    iv: OctetString<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaSlatAttr<'a> {
    entry_salt: OctetString<'a>,
    iteration_count: u32,
    key_size: u32,
    algorithm: MetaAlgorithm<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct MetaAlgorithm<'a> {
    oid: Oid<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct LoginPBE<'a> {
    cipher_text: OctetString<'a>,
    data: LoginData<'a>,
    encrypted: OctetString<'a>,
}

impl<'a> LoginPBE<'a> {
    pub fn decrypt(&self, global_salt: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        let (key, iv) = self.derive_key_and_iv(global_salt)?;
        des3_decrypt(&key, &iv, self.encrypted.as_cow())
    }

    fn derive_key_and_iv(&self, global_salt: &[u8]) -> BrowserVoyageResult<(Vec<u8>, Vec<u8>)> {
        Ok((global_salt.to_vec(), self.data.iv.as_cow().to_vec()))
    }
}

#[derive(Debug, PartialEq, DerSequence)]
pub struct LoginData<'a> {
    oid: Oid<'a>,
    iv: OctetString<'a>,
}

impl<'a> ASN1PBE<'a> {
    pub fn new(bytes: &'a [u8]) -> BrowserVoyageResult<Self> {
        if let Ok((_, nss_pbe)) = NssPBE::from_der(bytes) {
            return Ok(ASN1PBE::NssPBE(nss_pbe));
        }

        if let Ok((_, meta_pbe)) = MetaPBE::from_der(bytes) {
            return Ok(ASN1PBE::MetaPBE(meta_pbe));
        }

        if let Ok((_, login_pbe)) = LoginPBE::from_der(bytes) {
            return Ok(ASN1PBE::LoginPBE(login_pbe));
        }

        Err(BrowserVoyageError::DecryptionFailed(
            "Failed to decode ASN1PBE structure".into(),
        ))
    }

    pub fn decrypt(&self, global_salt: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        match self {
            ASN1PBE::NssPBE(nss_pbe) => nss_pbe.decrypt(global_salt),
            ASN1PBE::MetaPBE(meta_pbe) => meta_pbe.decrypt(global_salt),
            ASN1PBE::LoginPBE(login_pbe) => login_pbe.decrypt(global_salt),
        }
    }
}
