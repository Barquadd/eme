use std::{fs::write, io::Write, str};
use aes_gcm::aead::consts::U32;
use clap::Parser;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce
};
use std::io::{stdin, stdout};
use sha2::{Digest, Sha256};


#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    encrypt: bool,
    #[arg(short, long)]
    decrypt: bool,
    #[arg(short, long)]
    keyfile: Option<std::path::PathBuf>,
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

// may be redundant considering the above function
fn hash_vec_n_times(v: &Vec<u8>, n: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut result = v.clone();
    for _ in 0..n {
        let mut hasher_clone = hasher.clone();
        hasher_clone.update(&result);
        result = hasher_clone.finalize().to_vec();
        hasher.reset();
    }
    result
}

fn get_user_pass() -> Vec<u8> {
    print!("Enter the password: ");
    stdout().flush().unwrap();
    let mut password = String::new();
    stdin().read_line(&mut password).unwrap();
    let password = password.trim();

    let key: Vec<u8> = hash_string_n_times(&password, 100_000);
    key
}

fn main() {
    let args = Cli::parse();
    if {args.encrypt} == {args.decrypt} {
        panic!("You must specify either --encrypt or --decrypt");
    }
    println!("--> {} <--", if args.encrypt { "ENCRYPTING" } else { "DECRYPTING" });

    let key = match args.keyfile {
        Some(keyfile) => {
            let key = std::fs::read(keyfile).unwrap();
            let key: Vec<u8> = hash_vec_n_times(&key, 100_000);
            key
        }
        None => {
            // prompt for a password and do all that fun stuff if the user doesn't supply a keyfile
            let key: Vec<u8> = get_user_pass();
            key
        }
    };
    let key_g: GenericArray<_, U32> = GenericArray::clone_from_slice(&key);
    let cipher = Aes256Gcm::new(&key_g);

    if args.encrypt {
        // there's certainly a better way to do this
        let mut nonce_vec: Vec<u8> = vec![];
        for _ in 0..12 {
            nonce_vec.push(rand::random::<u8>());
        }
        let nonce = Nonce::from_slice(&nonce_vec);

        println!("Reading file...");
        let mut buffer: Vec<u8> = std::fs::read(args.path.clone()).expect("Failed to read file.");
        println!("Encrypting...");
        cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("Encryption failed.");
        nonce_vec.append(&mut buffer); // we want the nonce to be the first 96 bits in the file
        println!("Writing file...");
        write(args.path, nonce_vec).expect("Failed to write file.");
    }
    else if args.decrypt {
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
}
