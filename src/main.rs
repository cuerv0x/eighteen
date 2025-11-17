use hmac::Hmac;
use sha2::Sha256;
use rayon::prelude::*;
use std::io::{BufRead, BufReader};
use std::fs::File;
use std::env;

fn check_password(
    password: &[u8],
    salt: &str,
    iterations: u32,
    target_hash: &str,
) -> Option<String> {
    let mut output = [0u8; 32];

    match pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt.as_bytes(), iterations, &mut output) {
        Ok(_) => {
            let computed_hash = hex::encode(output);
            if computed_hash == target_hash {
                String::from_utf8(password.to_vec())
                    .ok()
                    .or_else(|| String::from_utf8_lossy(password).into_owned().into())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let salt = args.get(1)
        .map(|s| s.as_str())
        .unwrap_or("AMtzte0lG7yAbZIA");

    let iterations = args.get(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(600000);

    let target_hash = args.get(3)
        .map(|s| s.as_str())
        .unwrap_or("18adaa7e16f3e3d9428e8dd3252ee840ddd4972d9a9b5c4b6125da703f78a4e5");

    println!("Starting password cracker...");
    println!("Salt: {}", salt);
    println!("Iterations: {}", iterations);
    println!("Target hash: {}", target_hash);
    println!("Using {} threads", rayon::current_num_threads());

    let file = File::open("data/rockyou.txt").expect("Failed to open data/rockyou.txt");
    let reader = BufReader::new(file);

    let passwords: Vec<Vec<u8>> = reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|line| line.into_bytes())
        .collect();

    println!("Loaded {} passwords from rockyou.txt", passwords.len());
    println!("Starting parallel search...\n");

    let result = passwords
        .par_iter()
        .find_map_any(|password| {
            check_password(password, salt, iterations, target_hash)
        });

    match result {
        Some(password) => println!("\n✓ Password found: {}", password),
        None => println!("\n✗ Password not found in wordlist"),
    }
}
