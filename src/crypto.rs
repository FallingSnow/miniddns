use std::{io::Error, num::ParseIntError};

use log::trace;
use sha2::{Digest, Sha256};

pub fn validate_message<'a>(data: &'a str, secret: &[u8]) -> std::io::Result<&'a str> {
    // Remove auth- prefix
    let (_, msg) = data.split_once('-').ok_or(Error::new(
        std::io::ErrorKind::Other,
        "Failed to extract message",
    ))?;
    let (salt, msg) = msg.split_once('-').ok_or(Error::new(
        std::io::ErrorKind::Other,
        "Failed to extract salt/message",
    ))?;
    let (hash, message) = msg.split_once(' ').ok_or(Error::new(
        std::io::ErrorKind::Other,
        "Failed to extract data hash/message",
    ))?;
    let binary_hash = decode_hex(hash).map_err(|e| {
        Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to convert hash to hex {}", e),
        )
    })?;

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(secret);
    hasher.update(message);
    let calculated_hash = &hasher.finalize()[..];

    trace!("Salt: {salt}");
    trace!("Hash: {hash}");
    trace!("Message: {message}");
    trace!("Input Hash: {binary_hash:?}");
    trace!("Calculated Hash: {calculated_hash:?}");

    if binary_hash == calculated_hash {
        trace!("Valid message");
        return Ok(message);
    }

    Err(Error::new(
        std::io::ErrorKind::Other,
        "Invalid authentication",
    ))
}

// https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
