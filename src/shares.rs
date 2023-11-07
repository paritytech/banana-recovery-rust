use base64::Engine;
use bitvec::prelude::*;
use scrypt::{scrypt, Params};
use sha2::{Digest, Sha512};
use std::convert::TryInto;
use std::ops::RangeInclusive;
use xsalsa20poly1305::aead::{generic_array::GenericArray, Aead, KeyInit};
use xsalsa20poly1305::XSalsa20Poly1305;
use zeroize::Zeroize;

use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::Error;

/// To be valid character, the bits must be within certain bounds.
pub(crate) const BIT_RANGE: RangeInclusive<u32> = 3..=20;

/// Struct to store information about individual share.
/// `Share` information is decoded from the incoming share only.
/// In valid share the bits are within allowed limits,
/// this is always checked during share generation.
/// Share contains certain things that should better remain secret,
/// specifically content, nonce, and title, however nothing could be done with them unless
/// the passphrase is also known
#[derive(Debug)]
pub struct Share {
    version: Version,
    title: String,
    required_shards: usize,
    nonce: String,
    bits: u32,
    id: u32,
    content: Vec<u8>,
}

/// Version of banana split
/// currently only V1 exists, no version in json results in Undefined variant;
/// other versions are not supported and rejected;
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Version {
    Undefined,
    V1,
}

impl Share {
    /// Incoming new share is received as decoded qr code, in Vec<u8> format
    /// without QR header and padding
    pub fn new(share_vec: Vec<u8>) -> Result<Self, Error> {
        // transforming into String
        let share_string = match String::from_utf8(share_vec) {
            Ok(a) => a,
            Err(_) => return Err(Error::NotShareString),
        };

        // parsing the string with json
        let share_string_parsed = match json::parse(&share_string) {
            Ok(a) => a,
            Err(_) => return Err(Error::JsonParsing),
        };

        let version = match &share_string_parsed["v"] {
            json::JsonValue::Number(a) => {
                if a == &json::number::Number::from(1u32) {
                    Version::V1
                } else {
                    return Err(Error::VersionNotSupported(a.to_string()));
                }
            }
            json::JsonValue::Null => Version::Undefined,
            a => return Err(Error::VersionNotSupported(a.to_string())),
        };
        let title = share_string_parsed["t"].to_string();
        let required_shards = match &share_string_parsed["r"] {
            json::JsonValue::Number(a) => match a.to_string().parse::<usize>() {
                Ok(b) => b,
                Err(_) => return Err(Error::RequiredShardsNotSupported(a.to_string())),
            },
            a => return Err(Error::RequiredShardsNotSupported(a.to_string())),
        };
        let nonce = share_string_parsed["n"].to_string();
        let data = share_string_parsed["d"].to_string();

        // process the share data
        let share_chars: Vec<char> = data.chars().collect();
        // first share char is bits info in radix36 format
        let bits = match share_chars.first() {
            Some(a) => match a.to_digit(36) {
                Some(b) => {
                    // checking if bits value is within allowed limits
                    if BIT_RANGE.contains(&b) {
                        b
                    } else {
                        return Err(Error::BitsOutOfRange(b));
                    }
                }
                None => return Err(Error::ParseBit(*a)),
            },
            None => return Err(Error::EmptyShare),
        };
        // remaining piece is the share body;
        // is treated depending on the version;
        let share_body = match version {
            Version::Undefined => match hex::decode(String::from_iter(&share_chars[1..])) {
                Ok(a) => a,
                Err(_) => return Err(Error::UndefinedBodyNotHex),
            },
            Version::V1 => match BASE64.decode(String::from_iter(&share_chars[1..]).into_bytes()) {
                Ok(a) => a,
                Err(_) => return Err(Error::BodyNotBase64),
            },
        };

        // maximum possible number of shares, u32
        let max = 2u32.pow(bits) - 1; // do not allow bits exceed 20; 2^n with n 20 or below always fits in u32 limits

        // length of identificator piece in u8 units that should be cut from the beginning of the share_body;
        // could not exceed 4; in given limits, does not exceed 3;
        // starting zeroes are removed in length calculation
        let id_length = max.to_be_bytes().iter().skip_while(|x| x == &&0).count();

        // identifier piece (short Vec<u8>) and share content (Vec<u8>) separated
        let (identifier_piece, content) = match share_body.get(..id_length) {
            Some(a) => (a.to_vec(), share_body[id_length..].to_vec()),
            None => return Err(Error::ShareTooShort),
        };

        // current share id, u32
        let id = u32::from_be_bytes(
            [
                max.to_be_bytes()[..4 - id_length].to_vec(),
                identifier_piece,
            ]
            .concat()
            .try_into()
            .expect("fixed length of 4"),
        );

        Ok(Share {
            version,
            title,
            required_shards,
            nonce,
            bits,
            id,
            content,
        })
    }
    /// Function to print share title into user interface
    pub fn title(&self) -> String {
        self.title.to_owned()
    }
    /// Get the number of required shards
    pub fn required_shards(&self) -> usize {
        self.required_shards
    }
}

/// Struct to store information about share set.
/// Share could be added to the set only if
/// (1) its bits number same as in set,
/// (2) its share number is not yet encountered,
/// (3) its content length is same as the length of other contents in the set.
#[derive(Debug)]
pub struct ShareSet {
    version: Version,
    title: String,
    required_shards: usize,
    state: ShareSetState,
}

#[derive(Debug)]
pub enum ShareSetState {
    SetInProgress(SetInProgress),
    SetCombined(SetCombined),
}

#[derive(Debug)]
pub struct SetInProgress {
    bits: u32,
    id_set: Vec<u32>,
    content_length: usize,
    content_set: Vec<Vec<u8>>,
    nonce: String,
}

#[derive(Debug)]
pub struct SetCombined {
    data: Vec<u8>,
    nonce: Vec<u8>,
}

/// The next action to do for the share set at hand.
#[derive(Debug, PartialEq)]
pub enum NextAction {
    /// More shares are required for reconstruction.
    MoreShares {
        /// The current number of shares available.
        have: usize,
        /// Number of shares needed for recovery.
        need: usize,
    },
    /// The user password is needed.
    AskUserForPassword,
}

impl SetInProgress {
    /// Function to process the set of shares.
    /// To be called only on checked and ready set of shares,
    /// in other words does not check itself if the processing
    /// shares will produce a valid result.
    fn combine(&self) -> Result<SetCombined, Error> {
        // transpose content set
        // from
        // Vec[[share1[1], share1[2] ... share1[N]], [share2[1], share2[2] ... share2[N]] ... [shareM[1], shareM[2] ... shareM[N]]]
        // into
        // Vec[[share1[1], share2[1] ... shareM[1]], [share1[2], share2[2] ... shareM[2]] ... [share1[N], share2[N] ... shareM[N]]]
        let mut content_zipped: Vec<Vec<u32>> = Vec::with_capacity(self.content_length);
        for i in 0..self.content_length {
            let mut new: Vec<u32> = Vec::new();
            for j in 0..self.id_set.len() {
                new.push(self.content_set[j][i] as u32)
            }
            content_zipped.push(new);
        }

        // calculate logarithms and exponents in GF(2^n) for n = self.bits
        let (logs, exps) = generate_logs_and_exps(self.bits);

        // process and collect bit sequence from each element of content_zipped
        let mut result: BitVec<u32, Msb0> = BitVec::new();
        for content_zipped_element in content_zipped.iter() {
            // new element that will be processed; is calculated as u32, its value is always below 2^(self.bits);
            let new = lagrange(
                &self.id_set,
                content_zipped_element,
                &logs,
                &exps,
                self.bits,
            )?;

            // transform new element into new bitvec to operate on bits individually
            let new_bitvec: BitVec<u32, Msb0> = BitVec::from_vec(vec![new]);

            // in js code this crate follows, the bits string representation of new element (i.e. without leading zeroes)
            // was padded from left with zeroes so that the string length became multiple of (self.bits) number;
            // since the new element value is always below 2^(self.bits), this procedure effectively means keeping only
            // (self.bits) amount of bits from the element;
            // cut is the starting point after which the bits are retained;
            let cut = (32 - self.bits) as usize;

            // resulting bits are added into collection;
            result.extend_from_bitslice(&new_bitvec[cut..]);
        }
        // the js code this crate follows then calls for cutting all leading false bits
        // up until the first true, which serves as a padding marker,
        // cut padding marker as well, and then collect bytes with some padding on the left if necessary
        let result: BitVec<u8, Msb0> = result.into_iter().skip_while(|x| !*x).skip(1).collect();

        // transform result in its final form, Vec<u8>
        let data = result.into_vec();

        // process nonce, so that it is done before asking for a password
        let nonce = match BASE64.decode(self.nonce.as_bytes()) {
            Ok(a) => a,
            Err(_) => return Err(Error::NonceNotBase64),
        };
        // now the set is ready
        Ok(SetCombined { data, nonce })
    }
}

impl ShareSet {
    /// Initiating share set with first incoming share
    pub fn init(share: Share) -> Self {
        Self {
            version: share.version,
            title: share.title,
            required_shards: share.required_shards,
            state: ShareSetState::SetInProgress(SetInProgress {
                bits: share.bits,
                id_set: vec![share.id],
                content_length: share.content.len(),
                content_set: vec![share.content],
                nonce: share.nonce,
            }),
        }
    }
    /// Try to add another new share into existing set.
    /// Should be accessible through user interface only for ShareSetState::SetInProgress.
    pub fn try_add_share(&mut self, new: Share) -> Result<(), Error> {
        if let ShareSetState::SetInProgress(ref mut set_in_progress) = self.state {
            if new.version != self.version {
                return Err(Error::ShareVersionDifferent);
            } // should have same version

            if new.title != self.title {
                return Err(Error::ShareTitleDifferent);
            } // ... and same title

            if new.required_shards != self.required_shards {
                return Err(Error::ShareRequiredShardsDifferent);
            } // ... and same number of required shards

            if new.nonce != set_in_progress.nonce {
                return Err(Error::ShareNonceDifferent);
            } // ... and same nonce

            if new.bits != set_in_progress.bits {
                return Err(Error::ShareBitsDifferent);
            } // ... and bits

            if set_in_progress.id_set.contains(&new.id) {
                return Err(Error::ShareAlreadyInSet);
            } // ... also should be a new share

            if set_in_progress.content_length != new.content.len() {
                return Err(Error::ShareContentLengthDifferent);
            } // ... with same content length

            set_in_progress.id_set.push(new.id);
            set_in_progress.content_set.push(new.content);
            if set_in_progress.id_set.len() >= self.required_shards {
                let set_combined = set_in_progress.combine()?;
                self.state = ShareSetState::SetCombined(set_combined);
            }
        }
        Ok(())
    }
    /// Function for user interface to decide on next allowed action
    pub fn next_action(&self) -> NextAction {
        match &self.state {
            ShareSetState::SetInProgress(set_in_progress) => NextAction::MoreShares {
                have: set_in_progress.id_set.len(),
                need: self.required_shards,
            },
            ShareSetState::SetCombined(_) => NextAction::AskUserForPassword,
        }
    }
    /// Function to print set title into user interface
    pub fn title(&self) -> String {
        self.title.to_owned()
    }
    /// Function to recover the secret from the share set with known passphrase;
    /// `passphrase` is the passphrase generated together with qr set by banana split.
    /// Should be accessible through user interface only for ShareSetState::SetCombined.
    pub fn recover_with_passphrase(&self, passphrase: &str) -> Result<String, Error> {
        if let ShareSetState::SetCombined(SetCombined { data, nonce }) = &self.state {
            // hash title into salt
            let mut hasher = Sha512::new();
            hasher.update(self.title.as_bytes());
            let salt = hasher.finalize();

            // set up the parameters for scrypt
            let params =
                Params::new(15, 8, 1, Params::RECOMMENDED_LEN).expect("static checked params"); // default ones are used

            // set up output buffer for scrypt
            let mut key: Vec<u8> = [0; 32].to_vec(); // allocate here, empty output buffer is rejected

            // ... and scrypt them
            scrypt(passphrase.as_bytes(), &salt, &params, &mut key).map_err(Error::ScryptFailed)?;

            // set up cipher with key and decrypt secret using nonce
            let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&key[..]));
            match cipher.decrypt(GenericArray::from_slice(&nonce[..]), data.as_ref()) {
                Ok(a) => match String::from_utf8(a) {
                    // in case of successful vector-to-string conversion, vector does not get copied:
                    // https://doc.rust-lang.org/std/string/struct.String.html#method.from_utf8
                    // string ptr same as the one of former vector,
                    // string goes into output, no zeroize
                    Ok(b) => Ok(b),
                    // in case of conversion error, the vector goes into error;
                    // should be zeroized
                    Err(e) => {
                        let mut cleanup = e.into_bytes();
                        cleanup.zeroize();
                        Err(Error::DecodedSecretNotString)
                    }
                },
                Err(_) => Err(Error::DecodingFailed),
            }
        } else {
            Err(Error::NotReadyToDecode)
        }
    }
}

/// Primitive polynomials in Galois field GF(2^n), for 3 <= n <= 20.
/// Value n is bits value for shares, and is limited by BIT_RANGE constants.
/// Primitive polynomial values are taken from https://github.com/grempe/secrets.js/blob/master/secrets.js#L55
/// See https://mathworld.wolfram.com/PrimitivePolynomial.html for definitions
///
#[rustfmt::skip]
const PRIMITIVE_POLYNOMIALS: [u32; 18] = [
    3, // n = 3, or BIT_RANGE.start
    3,
    5,
    3,
    3,
    29,
    17,
    9,
    5,
    83,
    27,
    43,
    3,
    45,
    9,
    39,
    39,
    9, // n = 20, or MAX_BITS
];

/// Function to get primitive polynomial for given n in GF(2^n).
/// Already checked that n (i.e. bits) is within the acceptable range.
///
fn primitive_polynomial(n: u32) -> u32 {
    PRIMITIVE_POLYNOMIALS[n as usize - 3]
}

/// Function to generate a table of logarithms and exponents in GF(2^n) for given n (i.e. bits).
/// Already checked that n is within the acceptable range.
/// There are total n exponents and n logarithms generated, with values within the field.
/// All elements of field do not exceed (2^n-1) in value and could be recorded with n bits
/// (this is quite self-evident, but will be needed later on).
///
pub(crate) fn generate_logs_and_exps(n: u32) -> (Vec<Option<u32>>, Vec<u32>) {
    let size = 2u32.pow(n); // the number of elements in GF(2^n)

    let mut logs: Vec<Option<u32>> = Vec::with_capacity(size as usize);
    for _i in 0..size {
        logs.push(None)
    } // 0th element could not be reached during the cycling and is undefined

    let mut exps: Vec<u32> = Vec::with_capacity(size as usize);

    let mut x = 1;
    let primitive_polynomial = primitive_polynomial(n);
    for i in 0..size {
        exps.push(x);
        if logs[x as usize].is_none() {
            logs[x as usize] = Some(i)
        } // x = 1 is encountered twice
        x <<= 1; // left shift
        if x >= size {
            x ^= primitive_polynomial; // Bitwise XOR
            x &= size - 1; // Bitwise AND
        }
    }
    (logs, exps)
}

/// Function calculates Lagrange interpolation polynomial in GF(2^n).
/// x is vector of share identification numbers, and y is vector of certain number components from each share data;
/// x and y length are always identical, and do not exceed the maximum number of shares, 2^n-1;
/// logs and exps are the vectors of pre-calculated logarithms and exponents, with length 2^n;
///
pub(crate) fn lagrange(
    x: &[u32],
    y: &[u32],
    logs: &[Option<u32>],
    exps: &[u32],
    n: u32,
) -> Result<u32, Error> {
    let mut sum = 0;
    let size = 2u32.pow(n);
    let len = x.len();

    for i in 0..len {
        match logs.get(y[i] as usize) {
            Some(Some(a)) => {
                let mut product = *a;
                for j in 0..len {
                    if i != j {
                        let p1 = match logs.get(x[j] as usize) {
                            Some(a) => a.expect(
                                "x[j] is never zero, it is share number, numbering starts from 1",
                            ),
                            None => return Err(Error::LogOutOfRange(x[j])),
                        };
                        let p2 = match logs.get((x[i]^x[j]) as usize) {
                            Some(a) => a.expect("x[i] and x[j] are never equal for non-equal i and j, through Galois field properties"),
                            None => return Err(Error::LogOutOfRange(x[i]^x[j])),
                        };
                        product = ((size - 1) + product + p1 - p2) % (size - 1);
                    }
                }
                sum ^= exps[product as usize]; // product is always positive and below 2^n, exponent is always addressed correctly
            }
            Some(None) => (), // encountered the only undefined element (through Galois field properties), i.e. tried to calculate log[0]
            None => return Err(Error::LogOutOfRange(y[i])), // this should not happen, but values of y elements are u8 by decoding, and could in principle exceed 2^n number of elements in logs vector
        }
    }
    Ok(sum)
}
