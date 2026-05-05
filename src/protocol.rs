//! AirVPN authentication protocol implementation.
//!
//! This module implements the proprietary encrypted request/response protocol
//! used by AirVPN's API. The protocol works as follows:
//!
//! 1. Generate a random AES-256 key and IV.
//! 2. Encrypt the key+IV with the server's RSA public key (PKCS#1 v1.5) → `s`.
//! 3. Encrypt the request parameters with AES-256-CBC (PKCS7-padded) → `d`.
//! 4. POST `s` and `d` (base64-encoded, URL-encoded) to a bootstrap server.
//! 5. Decrypt the response with the same AES key and IV.
//!
//! This module exposes low-level helpers ([`encrypt_request`], [`decrypt_response`],
//! [`build_post_body`]) as well as the mid-level [`make_rsa_pubkey`] for key
//! construction. In most cases [`AirVPN::builder`] should be used instead
//! (Even I don't consider the low-level helpers very easy to grasp).
//! 
//!
//! [`AirVPN::builder`]: crate::AirVPN::builder

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use num_bigint_dig::BigUint;
use rand_core::{OsRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use crate::errors::{Error, Result};

/// The result of encrypting a request with the AirVPN protocol.
///
/// Contains the RSA-encrypted key/IV blob (`s`), the AES-encrypted data blob
/// (`d`), and the raw AES key and IV needed to decrypt the server's response.
pub struct EncryptedRequest {
    /// RSA-encrypted blob containing the AES key and IV (base64-encoded before POST).
    pub s: Vec<u8>,
    /// AES-256-CBC encrypted request parameters (base64-encoded before POST).
    pub d: Vec<u8>,
    /// The raw 32-byte AES-256 key. Keep this to decrypt the response.
    pub aes_key: Vec<u8>,
    /// The raw 16-byte AES-CBC initialization vector. Keep this to decrypt the response.
    pub aes_iv: Vec<u8>,
}

/// Encode a list of key-value byte pairs as a newline-delimited `base64(key):base64(value)` string.
///
/// This is the wire format the AirVPN API expects for both the RSA-encrypted
/// envelope (`s`) and the AES-encrypted payload (`d`).
pub fn encode_assoc(params: &[(Vec<u8>, Vec<u8>)]) -> String {
    params
        .iter()
        .map(|(key, value)| {
            let key_b64 = BASE64.encode(key);
            let val_b64 = BASE64.encode(value);
            format!("{}:{}", key_b64, val_b64)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Convenience wrapper around [`encode_assoc`] that accepts string pairs.
///
/// Each string is converted to its UTF-8 byte representation before encoding.
pub fn encode_assoc_str(params: &[(String, String)]) -> String {
    let byte_params: Vec<(Vec<u8>, Vec<u8>)> = params
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();
    encode_assoc(&byte_params)
}

/// Construct an RSA public key from base64-encoded modulus and exponent.
///
/// The modulus and exponent are the values found in the AirVPN manifest
/// (attributes `auth_rsa_modulus` and `auth_rsa_exponent`), or the
/// defaults in [`DEFAULT_RSA_MODULUS`]/[`DEFAULT_RSA_EXPONENT`].
///
/// [`DEFAULT_RSA_MODULUS`]: crate::constants::DEFAULT_RSA_MODULUS
/// [`DEFAULT_RSA_EXPONENT`]: crate::constants::DEFAULT_RSA_EXPONENT
pub fn make_rsa_pubkey(modulus_b64: &str, exponent_b64: &str) -> Result<RsaPublicKey> {
    let modulus_bytes = BASE64.decode(modulus_b64)?;
    let exponent_bytes = BASE64.decode(exponent_b64)?;
    let n = BigUint::from_bytes_be(&modulus_bytes);
    let e = BigUint::from_bytes_be(&exponent_bytes);
    RsaPublicKey::new(n, e).map_err(|e| Error::InvalidKey(e.to_string()))
}

/// Encrypt request parameters using the AirVPN protocol.
///
/// Returns an [`EncryptedRequest`] containing the two blobs (`s` and `d`)
/// to POST, along with the AES key/IV needed to decrypt the response.
///
/// # Arguments
///
/// * `parameters` — Key-value pairs to send (e.g. `act`, `login`, `password`).
/// * `rsa_modulus_b64` — Base64-encoded RSA modulus (from manifest or defaults).
/// * `rsa_exponent_b64` — Base64-encoded RSA exponent (from manifest or defaults).
pub fn encrypt_request(
    parameters: &[(String, String)],
    rsa_modulus_b64: &str,
    rsa_exponent_b64: &str,
) -> Result<EncryptedRequest> {
    let aes_key = new_aes_key();
    let aes_iv = new_aes_iv();

    let rsa_pubkey = make_rsa_pubkey(rsa_modulus_b64, rsa_exponent_b64)?;

    let param_s = encode_assoc(&[
        (b"key".to_vec(), aes_key.clone()),
        (b"iv".to_vec(), aes_iv.clone()),
    ]);
    let encrypted_s = rsa_pubkey
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, param_s.as_bytes())
        .map_err(|e| Error::Encryption(e.to_string()))?;

    let data = encode_assoc_str(parameters);
    let padded = pkcs7_pad(data.as_bytes());
    let encrypted_d = aes_cbc_encrypt(&aes_key, &aes_iv, &padded);

    Ok(EncryptedRequest {
        s: encrypted_s,
        d: encrypted_d,
        aes_key,
        aes_iv,
    })
}

/// Decrypt a response body received from an AirVPN bootstrap server.
///
/// `encrypted_data` is the raw bytes from the HTTP response body.
/// `aes_key` and `aes_iv` are from the [`EncryptedRequest`] used to make
/// the request.
pub fn decrypt_response(
    encrypted_data: &[u8],
    aes_key: &[u8],
    aes_iv: &[u8],
) -> Result<Vec<u8>> {
    let decrypted = aes_cbc_decrypt(aes_key, aes_iv, encrypted_data);
    pkcs7_unpad(&decrypted)
}

/// Build a URL-encoded POST body from the two encrypted blobs.
///
/// The result is suitable for use as the body of a `POST` request with
/// `Content-Type: application/x-www-form-urlencoded`.
pub fn build_post_body(encrypted_s: &[u8], encrypted_d: &[u8]) -> String {
    let s_encoded = BASE64.encode(encrypted_s);
    let d_encoded = BASE64.encode(encrypted_d);
    form_urlencoded::Serializer::new(String::new())
        .append_pair("s", &s_encoded)
        .append_pair("d", &d_encoded)
        .finish()
}

/// Apply PKCS#7 padding to `data`, adding between 1 and 16 bytes
/// so the result length is a multiple of the AES block size (16).
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let padding_len = 16 - (data.len() % 16);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    padded
}

/// Remove PKCS#7 padding. Returns an error if the padding is invalid.
fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::Decryption("empty data".into()));
    }
    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
        return Err(Error::Decryption("invalid PKCS7 padding".into()));
    }
    for &byte in &data[data.len() - padding_len..] {
        if byte != padding_len as u8 {
            return Err(Error::Decryption("invalid PKCS7 padding".into()));
        }
    }
    Ok(data[..data.len() - padding_len].to_vec())
}

/// Encrypt `data` with AES-256-CBC using the given 32-byte `key` and 16-byte `iv`.
fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("invalid AES-256 key");
    let mut ciphertext = Vec::with_capacity(data.len());
    let mut prev = iv.to_vec();

    for chunk in data.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        let mut ga = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut ga);
        prev.copy_from_slice(&ga);
        ciphertext.extend_from_slice(&ga);
    }

    ciphertext
}

/// Decrypt `data` with AES-256-CBC using the given 32-byte `key` and 16-byte `iv`.
///
/// **Note:** This does *not* remove padding. Call [`pkcs7_unpad`] on the result
/// if the input was PKCS7-padded.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("invalid AES-256 key");
    let mut plaintext = Vec::with_capacity(data.len());
    let mut prev = iv.to_vec();

    for chunk in data.chunks(16) {
        let mut ga = GenericArray::clone_from_slice(chunk);
        let encrypted = ga.clone();
        cipher.decrypt_block(&mut ga);
        let block: Vec<u8> = ga.to_vec();
        let mut decrypted = [0u8; 16];
        for i in 0..16 {
            decrypted[i] = block[i] ^ prev[i];
        }
        prev = encrypted.to_vec();
        plaintext.extend_from_slice(&decrypted);
    }

    plaintext
}

/// Generate a random 32-byte AES-256 key.
fn new_aes_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key.to_vec()
}

/// Generate a random 16-byte AES-CBC IV.
fn new_aes_iv() -> Vec<u8> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv.to_vec()
}

#[cfg(test)]
mod tests { // generated tests
    use super::*;

    #[test]
    fn test_encode_assoc_single_pair() {
        let params = vec![(b"key".to_vec(), b"value".to_vec())];
        let result = encode_assoc(&params);
        let parts: Vec<&str> = result.splitn(2, ':').collect();
        assert_eq!(BASE64.decode(parts[0]).unwrap(), b"key");
        assert_eq!(BASE64.decode(parts[1]).unwrap(), b"value");
    }

    #[test]
    fn test_encode_assoc_multiple_pairs() {
        let params = vec![
            (b"act".to_vec(), b"manifest".to_vec()),
            (b"login".to_vec(), b"user".to_vec()),
        ];
        let result = encode_assoc(&params);
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_encode_assoc_str() {
        let params = vec![
            ("act".to_string(), "manifest".to_string()),
            ("login".to_string(), "user".to_string()),
        ];
        let result = encode_assoc_str(&params);
        assert!(result.contains('\n'));
    }

    #[test]
    fn test_pkcs7_pad_aligns_to_16() {
        for len in 0..32 {
            let data = vec![0u8; len];
            let padded = pkcs7_pad(&data);
            assert_eq!(padded.len() % 16, 0);
            let pad_byte = padded[len];
            assert_eq!(pad_byte, (16 - len % 16) as u8);
        }
    }

    #[test]
    fn test_pkcs7_unpad_roundtrip() {
        for len in 0..48 {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let padded = pkcs7_pad(&data);
            let unpadded = pkcs7_unpad(&padded).unwrap();
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn test_pkcs7_unpad_empty_error() {
        let result = pkcs7_unpad(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkcs7_unpad_invalid_padding() {
        let mut data = vec![0u8; 16];
        data[15] = 3;
        assert!(pkcs7_unpad(&data).is_err());
    }

    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [42u8; 32];
        let iv = [17u8; 16];
        let plaintext = b"hello airvpn protocol test data!!";
        let padded = pkcs7_pad(plaintext);
        let encrypted = aes_cbc_encrypt(&key, &iv, &padded);
        let decrypted = aes_cbc_decrypt(&key, &iv, &encrypted);
        let unpadded = pkcs7_unpad(&decrypted).unwrap();
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_aes_cbc_roundtrip_various_lengths() {
        let key = [0xAB; 32];
        let iv = [0xCD; 16];
        for len in [0, 1, 15, 16, 31, 32, 63, 64, 127, 256] {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let padded = pkcs7_pad(&data);
            let encrypted = aes_cbc_encrypt(&key, &iv, &padded);
            let decrypted = aes_cbc_decrypt(&key, &iv, &encrypted);
            let unpadded = pkcs7_unpad(&decrypted).unwrap();
            assert_eq!(unpadded, data, "roundtrip failed for length {len}");
        }
    }

    #[test]
    fn test_make_rsa_pubkey_default_constants() {
        let key = make_rsa_pubkey(
            crate::constants::DEFAULT_RSA_MODULUS,
            crate::constants::DEFAULT_RSA_EXPONENT,
        );
        assert!(key.is_ok(), "should construct RSA key from default constants");
    }

    #[test]
    fn test_make_rsa_pubkey_invalid_base64() {
        let key = make_rsa_pubkey("not base64!!!???", "AQAB");
        assert!(key.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let params = vec![
            ("act".to_string(), "manifest".to_string()),
            ("login".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ];

        let enc = encrypt_request(
            &params,
            crate::constants::DEFAULT_RSA_MODULUS,
            crate::constants::DEFAULT_RSA_EXPONENT,
        )
        .unwrap();

        assert!(!enc.s.is_empty(), "encrypted 's' blob should not be empty");
        assert!(!enc.d.is_empty(), "encrypted 'd' blob should not be empty");
        assert_eq!(enc.aes_key.len(), 32, "AES key should be 32 bytes");
        assert_eq!(enc.aes_iv.len(), 16, "AES IV should be 16 bytes");

        let plaintext = aes_cbc_encrypt(&enc.aes_key, &enc.aes_iv, &pkcs7_pad(b"test data"));
        let decrypted = aes_cbc_decrypt(&enc.aes_key, &enc.aes_iv, &plaintext);
        let unpadded = pkcs7_unpad(&decrypted).unwrap();
        assert_eq!(unpadded, b"test data");
    }

    #[test]
    fn test_decrypt_response_roundtrip() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let original = b"hello world, this is a test of the decrypt function";

        let padded = pkcs7_pad(original);
        let encrypted = aes_cbc_encrypt(&key, &iv, &padded);

        let decrypted = decrypt_response(&encrypted, &key, &iv).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_build_post_body_contains_fields() {
        let body = build_post_body(b"encrypted_s_data", b"encrypted_d_data");
        assert!(body.starts_with("s="));
        assert!(body.contains("&d="));
    }

    #[test]
    fn test_build_post_body_values_are_base64() {
        let body = build_post_body(b"\x00\x01\x02", b"\xff\xfe\xfd");
        let parts: Vec<&str> = body.split('&').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].starts_with("s="));
        assert!(parts[1].starts_with("d="));
    }
}