use aes_gcm::{Aes256Gcm, KeyInit};
use cbc::cipher::BlockEncryptMut;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha384};
use rsa::RsaPrivateKey;
use ed25519_dalek::SigningKey;
use chacha20poly1305::ChaCha20Poly1305;

pub fn seal(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

pub fn stream(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

pub fn legacy_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(data);
    let mut old = Sha1::new();
    old.update(data);
    hasher.finalize().to_vec()
}

pub fn digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn weak_key() -> RsaPrivateKey {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 1024).unwrap()
}

pub fn signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

// RsaPrivateKey::new(&mut rng, 4096) appears only in this comment.
