use aes_gcm::aead::consts::U32;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use clap::{arg, command, value_parser};
use sha2::{Digest, Sha256};
use std::{fs::write, path::PathBuf};
use zeroize::Zeroize;

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
    let password = rpassword::prompt_password("Please enter a password: ").unwrap();
    let password = password.trim();
    let mut password: Vec<u8> = password.as_bytes().to_vec();
    let key: Vec<u8> = hash_vec_n_times(&password, 100_000);
    password.zeroize();
    key
}

fn main() {
    let m = command!()
        .arg(arg!(encrypt: -e --encrypt)
            .conflicts_with("decrypt")
            .required(true))
        .arg(arg!(decrypt: -d --decrypt)
            .conflicts_with("encrypt")
            .required(true))
        .arg(arg!(keyfile: -k --keyfile <keyfile>)
            .value_parser(value_parser!(PathBuf))
            .required(false))
        .arg(arg!(input: <path>)
            .value_parser(value_parser!(PathBuf))
            .required(true))
        .get_matches();

    let encrypt: &bool = m.get_one::<bool>("encrypt").unwrap();
    let decrypt: &bool = m.get_one::<bool>("decrypt").unwrap();
    let keyfile: Option<&PathBuf> = m.get_one::<PathBuf>("keyfile");
    let path: PathBuf = m.get_one::<PathBuf>("input").unwrap().to_path_buf();

    println!("--> {} <--", if *encrypt { "ENCRYPTING" } else { "DECRYPTING" });

    let key = match keyfile {
        Some(keyfile) => {
            println!("Reading keyfile...");
            let key = std::fs::read(keyfile).unwrap();
            let key: Vec<u8> = hash_vec_n_times(&key, 100_000);
            key
        }
        None => {
            let key: Vec<u8> = get_user_pass();
            key
        }
    };
    let key_g: GenericArray<_, U32> = GenericArray::clone_from_slice(&key);
    let cipher = Aes256Gcm::new(&key_g);

    if *encrypt {
        // there's certainly a better way to do this
        let mut nonce_vec: Vec<u8> = vec![];
        for _ in 0..12 {
            nonce_vec.push(rand::random::<u8>());
        }
        let nonce = Nonce::from_slice(&nonce_vec);

        println!("Reading file...");
        let mut buffer: Vec<u8> = std::fs::read(path.clone()).expect("Failed to read file.");
        println!("Encrypting...");
        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .expect("Encryption failed.");
        nonce_vec.append(&mut buffer); // we want the nonce to be the first 96 bits in the file
        println!("Writing file...");
        write(path, nonce_vec).expect("Failed to write file.");
    } else if *decrypt {
        println!("Reading file...");
        let buffer: Vec<u8> = std::fs::read(path.clone()).expect("Failed to read file.");
        // the first 12 bytes of the buffer is (should be) the nonce
        let (nonce_bytes, buffer) = buffer.split_at(12);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut buffer = buffer.to_vec();
        println!("Decrypting...");
        cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .expect("Decryption failed.");
        println!("Writing file...");
        write(path, buffer).expect("Failed to write file.");
    }
}
