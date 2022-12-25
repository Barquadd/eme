use std::{fs::write, io::Write};
use aes_gcm::aead::consts::U32;
use clap::Parser;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce
};
use std::io;
use sha2::{Digest, Sha256};


#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    encrypt: bool,
    #[arg(short, long)]
    decrypt: bool,
    path: std::path::PathBuf,
}

fn hash_string_n_times(s: &str, n: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut result = s.as_bytes().to_vec();
    for _ in 0..n {
        let mut hasher_clone = hasher.clone();
        hasher_clone.update(&result);
        result = hasher_clone.finalize().to_vec();
        hasher.reset();
    }
    result
}

fn main() {
    let args = Cli::parse();
    if args.encrypt {
        println!("--> ENCRYPTING <--");
        print!("Enter the password: ");
        // getting user password
        std::io::stdout().flush().unwrap();
        let mut password = String::new();
        io::stdin().read_line(&mut password).unwrap();
        let password = password.trim();

        let key: Vec<u8> = hash_string_n_times(&password, 100_000);

        let key_g: GenericArray<_, U32> = GenericArray::clone_from_slice(&key);

        let cipher = Aes256Gcm::new(&key_g);
        // there's certainly a better way to do this
        let mut nonce_vec: Vec<u8> = vec![];
        for _ in 0..12 {
            nonce_vec.push(rand::random::<u8>());
        }
        let nonce_vec_2 = nonce_vec.clone();
        let nonce = Nonce::from_slice(&nonce_vec_2);

        println!("Reading file...");
        let mut buffer: Vec<u8> = std::fs::read(args.path.clone()).expect("Failed to read file.");
        println!("Encrypting...");
        cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("Encryption failed.");
        nonce_vec.append(&mut buffer); // we want the nonce to be the first 96 bits in the file
        println!("Writing file...");
        write(args.path, nonce_vec).expect("Failed to write file.");
    }
    else if args.decrypt {
        println!("--> DECRYPTING <--");
        print!("Enter the password: ");
        std::io::stdout().flush().unwrap();
        let mut password = String::new();
        io::stdin().read_line(&mut password).unwrap();
        let password = password.trim();

        let key: Vec<u8> = hash_string_n_times(&password, 100_000);

        let key_g: GenericArray<_, U32> = GenericArray::clone_from_slice(&key);

        let cipher = Aes256Gcm::new(&key_g);

        println!("Reading file...");
        let buffer: Vec<u8> = std::fs::read(args.path.clone()).expect("Failed to read file.");
        // the first 12 bytes of the buffer is (should be) the nonce
        let (nonce_bytes, buffer) = buffer.split_at(12);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = buffer.to_vec();
        println!("Decrypting...");
        cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("Decryption failed.");
        println!("Writing file...");
        write(args.path, buffer).expect("Failed to write file.");
    }
    else {
        eprintln!("Please select a flag to use! Ex. -e")
    }
}
