use aes_gcm::aead::OsRng;
use base64::{engine::general_purpose, Engine as _};
use dirs2::data_dir;
use flate2::read::GzDecoder;
use pgp::{
    composed::{Deserializable, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
};
use std::{
    fs::File,
    io::{Error, Read, Result, Write},
};

pub const PUB_KEY_ENCODED: &str = r#"H4sIAAAAAAAAA32ST4+iQBDF7/0pvBMDKCoe5tDdtNAgCChgc4PWaRH8P4jw6YdxL5vd7FZSSeVVUqn3yxsO+0LEpN7AN/2BH6ElxQOHsAFarrDzsx0CcDJcknmhYSFmOw1DCFpZ2OgIBjvo6hK/u/rM2vM2Tgq5lDJJiavyqn2S85WU5eglgMOLLuhaZUnSa25WDTd1EZwW535+5qdS+OaPPi9YsntkybzO1lrjlajhp7mSj7Qa5EkkFTYj5MUcaGgJDYKbLh35J+NT+aaO7LVRrpOvpHiJ7hxE+P0tpDlsIhtlqwwIGC1xICwoWIxFSXFDyUJQAwZ03/dWQOjg8LcjuYuhr9VCPvq3dKYDtXD512aNGFrMR5vdqbvcTexUT0ml51QondsQOJFni4ksSewW1fQSp7m6j57Vvar5RAFY9TbKBnWuWngKTLQVDC8qcTkRlzsShMB0F8MgekPVJx1tqcNqqt7Ddn7parUEwe7A8bS6tXgV8YQ/CreGDMPegrAKSyMm6tlg9k824E84BvwF5y/v2TTvvbf1qbo7K3n7UA/j7dLUQSSiw1hRwoks0iqNrCr0ckXz2is0JG/8nDt8pdVxVzuezY8ty5t2bG1nz1c4my5Uv1WAvQ0dEZQf4MMrrxy840U84z/Z+wZTTypjoQIAAA=="#;

pub fn save_key(key: Vec<u8>) -> Result<()> {
    let decoded_key = general_purpose::STANDARD
        .decode(PUB_KEY_ENCODED)
        .map_err(|_| Error::other("Failed to decode public key"))?;

    let decoded_key_str = String::from_utf8(decoded_key)
        .map_err(|_| Error::other("Failed to convert decoded public key to string"))?;

    let mut gz = GzDecoder::new(decoded_key_str.as_bytes());

    let mut unzipped_key = String::new();

    gz.read_to_string(&mut unzipped_key)
        .map_err(|_| Error::other("Failed to unzip public key"))?;

    let (public_key, _) = SignedPublicKey::from_string(&unzipped_key)
        .map_err(|_| Error::other("Could not read public key"))?;

    let mut msg =
        MessageBuilder::from_bytes("", key).seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);

    msg.encrypt_to_key(OsRng, &public_key)
        .expect("recovery key encryption failure");

    let mut data_dir = data_dir().expect("Missing dara dir");
    data_dir.push("recovery_file");
    data_dir.set_extension("txt.key");
    let mut recovery_file = File::create(data_dir)?;

    recovery_file.write_all(
        &msg.to_vec(OsRng)
            .map_err(|_| Error::other("Failed to convert msg to vectore"))?,
    )?;
    Ok(())
}
