// bcrypt implementation in rust from scratch

// bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher, and presented in 1999 at the Usenix Security Symposium.

// bcrypt is a key derivation function, which is a one-way function that takes a password and a salt and returns a derived key.

mod bcrypt;

use bcrypt::{BCrypt, generate_salt};
use rpassword::read_password;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read password securely (without displaying it)
    print!("Enter password to hash: ");
    io::stdout().flush()?;
    let password = read_password()?;

    let salt = generate_salt();
    let bcrypt = BCrypt::new(10, salt)?;
    let hashed = bcrypt.hash(&password)?;
    
    println!("\nHashed password: {}", hashed);

    print!("\nEnter password to verify: ");
    io::stdout().flush()?;
    let verify_password = read_password()?;

    let is_valid = bcrypt.verify(&verify_password, &hashed)?;
    println!("\nPassword verification: {}", if is_valid { "success" } else { "failed" });

    Ok(())
}
