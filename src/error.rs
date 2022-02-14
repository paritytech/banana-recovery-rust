use crate::shares::{MAX_BITS, MIN_BITS};

#[derive(Debug)]
pub enum Error {
    BitsOutOfRange(u32),
    DecodedSecretNotString,
    DecodingFailed,
    EmptyShare,
    JsonParsing,
    LogOutOfRange(u32),
    NonceNotBase64,
    NotReadyToDecode,
    NotShareString,
    ParseBit(char),
    RequiredShardsNotSupported(String),
    ScryptFailed(scrypt::errors::InvalidOutputLen),
    ShareAlreadyInSet,
    ShareBitsDifferent,
    ShareContentLengthDifferent,
    ShareNonceDifferent,
    ShareRequiredShardsDifferent,
    ShareTitleDifferent,
    ShareTooShort,
    ShareVersionDifferent,
    UndefinedBodyNotHex,
    VersionNotSupported(String),
    V1BodyNotBase64,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.show())
    }
}

impl Error {
    pub fn show(&self) -> String {
        match self {
            Error::BitsOutOfRange(x) => format!("Bits in share data {} are outside of expected range [{},{}]. Likely the share is damaged.", x, MIN_BITS, MAX_BITS),
            Error::DecodedSecretNotString => String::from("Decoded secret could not be displayed as a string."),
            Error::DecodingFailed => String::from("Unable to decode the secret."),
            Error::EmptyShare => String::from("Share contains no data."),
            Error::JsonParsing => String::from("Unable to parse the input as a json object."),
            Error::LogOutOfRange(x) => format!("While processing, tried addressing log[{}] out of expected range. Likely the share is damaged.", x),
            Error::NonceNotBase64 => String::from("Nonce is not in base64 format"),
            Error::NotReadyToDecode => String::from("ShareSet was not ready to decode. Should not ba here."),
            Error::NotShareString => String::from("Received qr code could not be read as a string."),
            Error::ParseBit(c) => format!("Unable to parse first data char {} as a number in radix36 format", c),
            Error::RequiredShardsNotSupported(x) => format!("Required shards value {} has unsupported format.", x),
            Error::ScryptFailed(x) => format!("Scrypt calculation failed. {}", x),
            Error::ShareAlreadyInSet => String::from("Share is already in the set."),
            Error::ShareBitsDifferent => String::from("Share could not be added to the set, because its bits setting is different."),
            Error::ShareContentLengthDifferent => String::from("Share could not be added to the set, because its content length is different."),
            Error::ShareNonceDifferent => String::from("Share could not be added to the set, because its nonce is different."),
            Error::ShareRequiredShardsDifferent => String::from("Share could not be added to the set, because it has different number of required shards."),
            Error::ShareTitleDifferent => String::from("Share could not be added to the set, because its title is different."),
            Error::ShareTooShort => String::from("Share content is too short to separate share id properly. Likely the share is damaged."),
            Error::ShareVersionDifferent => String::from("Share could not be added to the set, because its version is different."),
            Error::UndefinedBodyNotHex => String::from("Share with undefined version was expected to have hexadecimal content."),
            Error::VersionNotSupported(x) => format!("Version {} is not supported.", x),
            Error::V1BodyNotBase64 => String::from("Share with version V1 was expected to have content in base64 format."),
        }
    }
}
