mod bcrypt;

use bcrypt::{BCrypt, generate_salt};
use rpassword::read_password;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
