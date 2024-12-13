# BCrypt Implementation in Rust

A from-scratch implementation of the BCrypt password hashing algorithm in Rust. This project provides a secure way to hash passwords using the BCrypt algorithm, which is designed to be slow and computationally intensive to prevent brute-force attacks.

## Features

- Pure Rust implementation of BCrypt
- Configurable cost factor (work factor)
- Secure random salt generation
- Password verification
- Unicode password support with NFKC normalization
- Constant-time comparison for password verification
- Comprehensive test suite

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
crypt_rust = "0.1.0"
```

## Usage

### Basic Usage

```rust
use crypt_rust::{BCrypt, generate_salt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random salt
    let salt = generate_salt();
    let cost = rand::thread_rng().gen_range(4..=31);
    // Creating a new BCRYPT Instance with cost factor random
    let bcrypt = BCrypt::new(cost, salt)?;
    let password = "my_password";
    let hash = bcrypt.hash(password)?;
    println!("Hashed password: {}", hash);

    //Verify the password
    let is_valid = bcrypt.verify(password, &hash)?;
    println!("Password is valid: {}", is_valid);

    Ok(())
}
```

### Command Line Interface

The project includes a command line interface for hashing and verifying passwords.

```bash
cargo run 
```
This will prompt you to:
1. Enter a password to hash
2. Display the hashed password
3. Verifying password by entering the same password

## Security Features

- **Cost Factor**: The cost factor determines the number of rounds of hashing. A higher cost factor makes the hashing process slower, making it harder to perform brute-force attacks.
- **Salt**: A random salt is generated for each password hash to ensure that the same password will produce a different hash on each run.
- **Unicode Normalization**: The password is normalized to NFC form before hashing to ensure that the same password will produce the same hash regardless of the Unicode normalization form.
- **Constant-time Comparison**: The password verification is implemented in a constant-time manner to prevent timing attacks.


## Build from source

```bash
git clone https://github.com/awwyushh/crypt_rust.git
cd bcrypt_rust
cargo build --release
```

## Run Tests

```bash
cargo test
```

## License

This project is open-sourced under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Ayush Shukla](https://github.com/awwyushh)



