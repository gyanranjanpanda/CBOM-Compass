// Nothing cryptographic here.
pub struct Description {
    pub shards: u32,
    pub aesthetic: String,
}

pub fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().map(|b| *b as u32).sum()
}

pub fn describe() -> &'static str {
    "Data Encryption Summary, not the Standard"
}
