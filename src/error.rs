use crate::shares::BIT_RANGE;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("Bits in share data {0} are outside of expected range [{range:?}]. Likely the share is damaged.", range=BIT_RANGE)]
    BitsOutOfRange(u32),

    #[error("Decoded secret could not be displayed as a string.")]
    DecodedSecretNotString,

    #[error("Unable to decode the secret.")]
    DecodingFailed,

    #[error("Share contains no data.")]
    EmptyShare,

    #[error("Unable to parse the input as a json object.")]
    JsonParsing,

    #[error("While processing, tried addressing log[{0}] out of expected range. Likely the share is damaged.")]
    LogOutOfRange(u32),

    #[error("Nonce is not in base64 format")]
    NonceNotBase64,

    #[error("ShareSet was not ready to decode. Should not ba here.")]
    NotReadyToDecode,

    #[error("Received qr code could not be read as a string.")]
    NotShareString,

    #[error("Unable to parse first data char '{0}' as a number in radix36 format")]
    ParseBit(char),

    #[error("Required shards value {0} has unsupported format.")]
    RequiredShardsNotSupported(String),

    #[error("Scrypt calculation failed.")]
    ScryptFailed(#[from] scrypt::errors::InvalidOutputLen),

    #[error("Share is already in the set.")]
    ShareAlreadyInSet,

    #[error("Share could not be added to the set, because its bits setting is different.")]
    ShareBitsDifferent,

    #[error("Share could not be added to the set, because its content length is different.")]
    ShareContentLengthDifferent,

    #[error("Share could not be added to the set, because its nonce is different.")]
    ShareNonceDifferent,

    #[error(
        "Share could not be added to the set, because it has different number of required shards."
    )]
    ShareRequiredShardsDifferent,

    #[error("Share could not be added to the set, because its title is different.")]
    ShareTitleDifferent,

    #[error(
        "Share content is too short to separate share id properly. Likely the share is damaged."
    )]
    ShareTooShort,

    #[error("Share could not be added to the set, because its version is different.")]
    ShareVersionDifferent,

    #[error("Share with undefined version was expected to have hexadecimal content.")]
    UndefinedBodyNotHex,

    #[error("Version {0} is not supported.")]
    VersionNotSupported(String),

    #[error("Share with version V1 was expected to have content in base64 format.")]
    BodyNotBase64,
}
