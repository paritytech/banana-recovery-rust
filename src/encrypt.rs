use crate::shares::generate_logs_and_exps;
use crate::Error;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bitvec::macros::internal::funty::Fundamental;
use crypto_secretbox::aead::{generic_array::GenericArray, Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use rand::RngCore;
use scrypt::{scrypt, Params};
use serde::Serialize;
use sha2::{Digest, Sha512};

#[derive(Serialize)]
struct Share {
    v: u8,
    t: String,
    r: usize,
    d: String,
    n: String,
}

/// Encrypts a secret and returns a set of shares.
pub fn encrypt(
    secret: &str,
    title: &str,
    passphrase: &str,
    total_shards: usize,
    required_shards: usize,
) -> Result<Vec<String>, Error> {
    // hash title into salt
    let salt = hash_string(title);

    // set up the parameters for scrypt
    let params = Params::new(15, 8, 1, 32).expect("static checked params"); // default ones are used

    // set up output buffer for scrypt
    let mut key: Vec<u8> = [0; 32].to_vec(); // allocate here, empty output buffer is rejected

    // ... and scrypt them
    scrypt(passphrase.as_bytes(), &salt, &params, &mut key).map_err(Error::ScryptFailed)?;

    let mut nonce = [0; 24].to_vec(); // allocate here, empty output buffer is rejected
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut nonce);

    // set up cipher with key and decrypt secret using nonce
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key[..]));
    let encrypted = cipher
        .encrypt(GenericArray::from_slice(&nonce), secret.as_bytes())
        .map_err(|_| Error::EncryptionFailed)?;

    let shares = share(&encrypted, total_shards, required_shards)?;
    let nonce = BASE64.encode(nonce);

    Ok(shares
        .into_iter()
        .map(|share| {
            let share = Share {
                v: 1,
                t: title.to_string(),
                r: required_shards,
                d: share,
                n: nonce.clone(),
            };
            serde_json::to_string(&share).unwrap()
        })
        .collect())
}

///
pub(crate) fn hash_string(s: &str) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

fn share(secret: &[u8], num_shares: usize, required_shards: usize) -> Result<Vec<String>, Error> {
    if num_shares < 2 {
        return Err(Error::TooFewShares);
    }
    if num_shares < required_shards {
        return Err(Error::TooFewShares);
    }
    let bits = 8u8;
    let max_shares = 2u32.pow(bits as u32) - 1; // do not allow bits exceed 20; 2^n with n 20 or below always fits in u32 limits
    if num_shares > max_shares as usize {
        return Err(Error::TooManyShares(max_shares));
    }

    // Security:
    // For additional security, pad in multiples of 128 bits by default.
    // A small trade-off in larger share size to help prevent leakage of information
    // about small-ish secrets and increase the difficulty of attacking them.
    let pad_length = 7;
    let left_pad = pad_length - (secret.len() + 1) % pad_length;

    let mut to_split = vec![0u8; left_pad];
    to_split.extend(vec![1u8]);
    to_split.extend(secret);

    // Vec[[share1[1], share2[1] ... shareM[1]], [share1[2], share2[2] ... shareM[2]] ... [share1[N], share2[N] ... shareM[N]]]
    let splits: Vec<Vec<u8>> = to_split
        .into_iter()
        .map(|x| get_shares(x, num_shares, required_shards, bits))
        .collect();

    // to Vec[[share1[1], share1[2] ... share1[N]], [share2[1], share2[2] ... share2[N]] ... [shareM[1], shareM[2] ... shareM[N]]]
    let mut x = Vec::with_capacity(num_shares);
    for i in 0..num_shares {
        let mut y = Vec::with_capacity(splits.len());
        for split in &splits {
            y.push(split[i]);
        }
        x.push(y);
    }

    Ok(x.iter()
        .enumerate()
        .map(|(idx, data)| construct_public_share_string(bits, idx.as_u8() + 1, data))
        .collect())
}

// Generates a random shamir pool for a given secret, returns share points.
fn get_shares(secret: u8, num_shares: usize, threshold: usize, bits: u8) -> Vec<u8> {
    let mut coeffs = vec![0; threshold - 1];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut coeffs);
    let mut poly = vec![secret];
    poly.extend(coeffs);
    let (logs, exps) = generate_logs_and_exps(bits as u32);
    (1..num_shares + 1)
        .map(|x| horner(x as u8, &poly, &logs, &exps, bits as u32))
        .collect()
}

// Polynomial evaluation at `x` using Horner's Method
// NOTE: fx=fx * x + coeff[i] ->  exp(log(fx) + log(x)) + coeff[i],
//       so if fx===0, just set fx to coeff[i] because
//       using the exp/log form will result in incorrect value
fn horner(x: u8, coeffs: &[u8], logs: &[Option<u32>], exps: &[u32], n: u32) -> u8 {
    let logx = logs[x as usize]
        .expect("logs[x] is never zero, it is share number, numbering starts from 1");
    let mut fx = 0;
    let max_shares = 2u32.pow(n) - 1;
    for i in coeffs.iter().rev() {
        if fx != 0 {
            let exp = (logx + logs[fx as usize].expect("log(x) is not defined")) % max_shares;
            fx = exps[exp as usize] ^ *i as u32;
        } else {
            fx = *i as u32;
        }
    }
    fx.try_into().expect("failed to convert result to u8")
}

fn construct_public_share_string(bits: u8, id: u8, data: &[u8]) -> String {
    let mut combined = vec![id];
    combined.extend_from_slice(data);
    format!(
        "{}{}",
        format_radix(bits as u32, 36),
        BASE64.encode(combined),
    )
}

fn format_radix(mut x: u32, radix: u32) -> String {
    let mut result = vec![];
    loop {
        let m = x % radix;
        x /= radix;

        result.push(std::char::from_digit(m, radix).expect("bad radix (< 2 or > 36)"));
        if x == 0 {
            break;
        }
    }
    result.into_iter().rev().collect()
}
