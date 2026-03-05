//! Hash cracking logic — PreimageOracle setup and result types.

use std::path::Path;

use preimage::hashing::{
    Lm, Ntlm, MySql41, Md5Md5, Md5, Sha1, Md2, Md4,
    Sha256, Sha224, Sha384, Sha512, Whirlpool, Ripemd160, QubesV31,
};
use preimage::{PreimageOracle, LookupMatch};

/// A cracked hash result for one input hash.
pub struct CrackResult {
    pub hash: String,
    pub matches: Vec<CrackMatch>,
    /// True when the input is not a valid hash format (non-hex, odd-length, or too short).
    pub format_error: bool,
}

/// A single match found for a hash.
pub struct CrackMatch {
    pub plaintext: String,
    pub algorithm_name: String,
    pub is_full_match: bool,
    /// Only present for partial matches — the full recomputed hash
    pub full_hash: Option<String>,
}

/// Initialize the PreimageOracle from a directory containing .idx and .lst files.
///
/// Registers all 17 lookup tables in the same order as PHP's CrackHashes.php.
/// Panics if any table or dictionary file is missing or fails to load — a cracking
/// service that silently skips tables gives false "Not found" answers.
pub fn init_oracle(cracking_dir: &Path) -> PreimageOracle {
    let mut oracle = PreimageOracle::new();
    let realuniq = cracking_dir.join("REALUNIQ.lst");
    let hugelist = cracking_dir.join("HUGELIST.lst");

    // Register in exact PHP order (determines match priority)
    let tables: Vec<(&str, &str, Box<dyn preimage::HashAlgorithm>)> = vec![
        ("lm",         "lm.idx",         Box::new(Lm)),
        ("ntlm",       "ntlm.idx",       Box::new(Ntlm)),
        ("mysql4.1+",  "mysql4.1+.idx",  Box::new(MySql41)),
        ("md5md5",     "md5md5.idx",     Box::new(Md5Md5)),
        ("md5",        "md5.idx",        Box::new(Md5)),
        ("sha1",       "sha1.idx",       Box::new(Sha1)),
        ("md2",        "md2.idx",        Box::new(Md2)),
        ("md4",        "md4.idx",        Box::new(Md4)),
        ("sha256",     "sha256.idx",     Box::new(Sha256)),
        ("sha224",     "sha224.idx",     Box::new(Sha224)),
        ("sha384",     "sha384.idx",     Box::new(Sha384)),
        ("sha512",     "sha512.idx",     Box::new(Sha512)),
        ("whirlpool",  "whirlpool.idx",  Box::new(Whirlpool)),
        ("ripemd160",  "ripemd160.idx",  Box::new(Ripemd160)),
        ("qubesv3.1",  "qubesv3.1.idx",  Box::new(QubesV31)),
        // Huge tables (fallback for md5/sha1)
        ("md5-huge",   "md5-huge.idx",   Box::new(Md5)),
        ("sha1-huge",  "sha1-huge.idx",  Box::new(Sha1)),
    ];

    for (label, idx_name, algorithm) in tables {
        let idx_path = cracking_dir.join(idx_name);
        let dict = if label.contains("huge") { &hugelist } else { &realuniq };
        oracle
            .register_boxed(label, algorithm, &idx_path, dict)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to load table '{}' (index: {}, dict: {}): {}",
                    label,
                    idx_path.display(),
                    dict.display(),
                    e,
                )
            });
        tracing::info!("Loaded table: {}", label);
    }

    oracle
}

/// Check whether a string looks like a valid hash in hex format.
///
/// Matches PHP's CrackHashes validation: must be at least 16 hex characters,
/// even length, and contain only hex digits.
fn is_valid_hash_hex(s: &str) -> bool {
    s.len() >= 16 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Crack a list of hashes using the oracle.
///
/// Returns one CrackResult per input hash, in the same order.
/// Invalid hash formats (non-hex, odd-length, too short) are returned with
/// `format_error: true` and are not sent to the oracle.
pub fn crack_hashes(oracle: &PreimageOracle, hashes: &[String]) -> Vec<CrackResult> {
    // Separate valid hashes from format errors, preserving original indices.
    let mut valid_indices = Vec::new();
    let mut valid_hashes = Vec::new();
    let mut output: Vec<Option<CrackResult>> = (0..hashes.len()).map(|_| None).collect();

    for (i, hash) in hashes.iter().enumerate() {
        if is_valid_hash_hex(hash) {
            valid_indices.push(i);
            valid_hashes.push(hash.as_str());
        } else {
            output[i] = Some(CrackResult {
                hash: hash.clone(),
                matches: Vec::new(),
                format_error: true,
            });
        }
    }

    // Crack the valid hashes as a batch.
    let results = oracle.crack(&valid_hashes, true); // early_exit = true (matches PHP)

    for (idx, result) in valid_indices.into_iter().zip(results.into_iter()) {
        let matches = result
            .matches
            .iter()
            .map(|m| {
                let plaintext = m.lookup_match.plaintext_lossy().into_owned();
                let (is_full, full_hash) = match &m.lookup_match {
                    LookupMatch::Full { .. } => (true, None),
                    LookupMatch::Partial { recomputed_hash, .. } => {
                        (false, Some(hex::encode(recomputed_hash)))
                    }
                };
                let algorithm_name = match &m.lookup_match {
                    LookupMatch::Full { algorithm, .. }
                    | LookupMatch::Partial { algorithm, .. } => {
                        algorithm.name().to_string()
                    }
                };
                CrackMatch {
                    plaintext,
                    algorithm_name,
                    is_full_match: is_full,
                    full_hash,
                }
            })
            .collect();

        output[idx] = Some(CrackResult {
            hash: result.queried_hash,
            matches,
            format_error: false,
        });
    }

    output
        .into_iter()
        .map(|r| r.expect("every hash index must be populated"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hash_hex_accepts_valid_hashes() {
        // 16 hex chars (minimum)
        assert!(is_valid_hash_hex("0123456789abcdef"));
        // 32 hex chars (md5 length)
        assert!(is_valid_hash_hex("5d41402abc4b2a76b9719d911017c592"));
        // 40 hex chars (sha1 length)
        assert!(is_valid_hash_hex("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"));
        // Upper-case hex
        assert!(is_valid_hash_hex("5D41402ABC4B2A76B9719D911017C592"));
        // Mixed case
        assert!(is_valid_hash_hex("5d41402ABC4b2a76b9719d911017c592"));
    }

    #[test]
    fn valid_hash_hex_rejects_too_short() {
        assert!(!is_valid_hash_hex("0123456789abcde")); // 15 chars
        assert!(!is_valid_hash_hex("abcdef")); // 6 chars
        assert!(!is_valid_hash_hex("")); // empty
    }

    #[test]
    fn valid_hash_hex_rejects_odd_length() {
        assert!(!is_valid_hash_hex("0123456789abcdef0")); // 17 chars
    }

    #[test]
    fn valid_hash_hex_rejects_non_hex() {
        assert!(!is_valid_hash_hex("zzzzzzzzzzzzzzzz")); // 16 non-hex chars
        assert!(!is_valid_hash_hex("5d41402abc4b2a76b9719d911017c59g")); // trailing 'g'
        assert!(!is_valid_hash_hex("hello world 1234")); // spaces
    }
}
