use std::error::Error;
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug)]
pub enum BCryptError {
    InvalidCost(String),
    InvalidSaltLength(String),
    InvalidPassword(String),
    InternalError(String),
}

impl fmt::Display for BCryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BCryptError::InvalidCost(msg) => write!(f, "Invalid cost: {}", msg),
            BCryptError::InvalidSaltLength(msg) => write!(f, "Invalid salt length: {}", msg),
            BCryptError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            BCryptError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl Error for BCryptError {}

const BCRYPT_SALT_LEN: usize = 16;
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;
const BCRYPT_BASE64: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub struct BCrypt {
    cost: u32,
    salt: [u8; BCRYPT_SALT_LEN],
}

impl BCrypt {
    pub fn new(cost: u32, salt: [u8; BCRYPT_SALT_LEN]) -> Result<Self, BCryptError> {
        if cost < MIN_COST || cost > MAX_COST {
            return Err(BCryptError::InvalidCost(
                format!("Cost must be between {} and {}", MIN_COST, MAX_COST)
            ));
        }

        Ok(BCrypt { cost, salt })
    }

    fn normalize_password(password: &str) -> Result<Vec<u8>, BCryptError> {
        let normalized = password.nfkc().collect::<String>();
        let mut bytes = normalized.as_bytes().to_vec();
        
        if bytes.contains(&0) {
            return Err(BCryptError::InvalidPassword("Password contains null bytes".to_string()));
        }
        bytes.push(0);
        
        if bytes.len() > 72 {
            bytes.truncate(72);
        }
        
        Ok(bytes)
    }

    pub fn hash(&self, password: &str) -> Result<String, BCryptError> {
        let normalized_password = Self::normalize_password(password)?;
        
        if normalized_password.is_empty() {
            return Err(BCryptError::InvalidPassword("Password cannot be empty".to_string()));
        }

        let mut state = Blowfish::init_state();
        self.eks_blowfish_setup(&mut state, &normalized_password, &self.salt)?;

        let mut ctext = [0u32; 3];
        for _ in 0..64 {
            for i in 0..3 {
                ctext[i] = state.encrypt_block(ctext[i]);
            }
        }

        let mut output = String::new();
        output.push_str("$2a$");
        output.push_str(&format!("{:02}", self.cost));
        output.push('$');
        output.push_str(&base64_encode(&self.salt));
        output.push_str(&base64_encode(&ctext_to_bytes(&ctext)));

        Ok(output)
    }

    fn eks_blowfish_setup(&self, state: &mut Blowfish, password: &[u8], salt: &[u8]) 
        -> Result<(), BCryptError> {
        let rounds = 1u32.checked_shl(self.cost)
            .ok_or_else(|| BCryptError::InvalidCost("Cost factor too high".to_string()))?;
        
        state.expand_key(password);
        
        for _ in 0..rounds {
            state.expand_key(salt);
            state.expand_key(password);
        }
        Ok(())
    }

    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, BCryptError> {
        let generated = self.hash(password)?;
        Ok(constant_time_compare(hash.as_bytes(), generated.as_bytes()))
    }
}

struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    fn init_state() -> Self {
        Blowfish {
            p: [
                0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
                0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
                0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
            ],
            s: [[0u32; 256]; 4],
        }
    }

    fn encrypt_block(&self, mut block: u32) -> u32 {
        let mut left = (block >> 16) as u32;
        let mut right = (block & 0xffff) as u32;

        for i in 0..16 {
            left ^= self.p[i];
            right ^= self.f(left);
            std::mem::swap(&mut left, &mut right);
        }
        std::mem::swap(&mut left, &mut right);

        right ^= self.p[16];
        left ^= self.p[17];

        ((left << 16) | right) as u32
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut j = 0;
        for i in 0..18 {
            let mut data = 0u32;
            for _ in 0..4 {
                data = (data << 8) | key[j % key.len()] as u32;
                j = j.wrapping_add(1);
            }
            self.p[i] ^= data;
        }

        let mut block = 0u32;
        for i in 0..9 {
            block = self.encrypt_block(block);
            self.p[i * 2] = (block >> 16) as u32;
            self.p[i * 2 + 1] = (block & 0xffff) as u32;
        }

        for i in 0..4 {
            for j in 0..128 {
                block = self.encrypt_block(block);
                self.s[i][j * 2] = (block >> 16) as u32;
                self.s[i][j * 2 + 1] = (block & 0xffff) as u32;
            }
        }
    }

    fn f(&self, x: u32) -> u32 {
        let a = ((x >> 24) & 0xff) as usize;
        let b = ((x >> 16) & 0xff) as usize;
        let c = ((x >> 8) & 0xff) as usize;
        let d = (x & 0xff) as usize;

        ((self.s[0][a] + self.s[1][b]) ^ self.s[2][c]) + self.s[3][d]
    }
}

fn base64_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity((input.len() * 4 + 2) / 3);
    
    for chunk in input.chunks(3) {
        let b1 = chunk[0] as u32;
        let b2 = chunk.get(1).map(|&b| b as u32).unwrap_or(0);
        let b3 = chunk.get(2).map(|&b| b as u32).unwrap_or(0);

        let triple = (b1 << 16) | (b2 << 8) | b3;

        output.push(BCRYPT_BASE64[(triple >> 18) as usize] as char);
        output.push(BCRYPT_BASE64[(triple >> 12 & 0x3F) as usize] as char);
        
        if chunk.len() > 1 {
            output.push(BCRYPT_BASE64[(triple >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(BCRYPT_BASE64[(triple & 0x3F) as usize] as char);
        }
    }

    output
}

fn ctext_to_bytes(ctext: &[u32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(ctext.len() * 4);
    for &value in ctext {
        result.extend_from_slice(&value.to_be_bytes());
    }
    result
}

pub fn generate_salt() -> [u8; BCRYPT_SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; BCRYPT_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}