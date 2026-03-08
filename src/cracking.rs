//! Hash cracking logic — PreimageOracle setup and result types.

use std::path::Path;

use preimage::hashes::{
    LM, NTLM, MYSQL41, MD5MD5, MD5, SHA1, MD2, MD4,
    SHA256, SHA224, SHA384, SHA512, WHIRLPOOL, RIPEMD160, QUBESV31,
    HashAlgorithm,
};
use preimage::{PreimageOracle, HashResult};

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
    let tables: Vec<(&str, &str, &'static dyn HashAlgorithm)> = vec![
        ("lm",         "lm.idx",         LM),
        ("ntlm",       "ntlm.idx",       NTLM),
        ("mysql4.1+",  "mysql4.1+.idx",  MYSQL41),
        ("md5md5",     "md5md5.idx",     MD5MD5),
        ("md5",        "md5.idx",        MD5),
        ("sha1",       "sha1.idx",       SHA1),
        ("md2",        "md2.idx",        MD2),
        ("md4",        "md4.idx",        MD4),
        ("sha256",     "sha256.idx",     SHA256),
        ("sha224",     "sha224.idx",     SHA224),
        ("sha384",     "sha384.idx",     SHA384),
        ("sha512",     "sha512.idx",     SHA512),
        ("whirlpool",  "whirlpool.idx",  WHIRLPOOL),
        ("ripemd160",  "ripemd160.idx",  RIPEMD160),
        ("qubesv3.1",  "qubesv3.1.idx",  QUBESV31),
        // Huge tables (fallback for md5/sha1)
        ("md5-huge",   "md5-huge.idx",   MD5),
        ("sha1-huge",  "sha1-huge.idx",  SHA1),
    ];

    for (label, idx_name, algorithm) in tables {
        let idx_path = cracking_dir.join(idx_name);
        let dict = if label.contains("huge") { &hugelist } else { &realuniq };
        oracle
            .register(label, algorithm, &idx_path, dict)
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

/// Crack a list of hashes using the oracle.
///
/// Returns one CrackResult per input hash, in the same order.
/// Invalid hash formats (non-hex, odd-length, too short) are returned with
/// `format_error: true` — validation is handled by the oracle.
pub fn crack_hashes(oracle: &PreimageOracle, hashes: &[String]) -> Vec<CrackResult> {
    let hash_refs: Vec<&str> = hashes.iter().map(|h| h.as_str()).collect();
    let results = oracle.crack(&hash_refs, true); // early_exit = true (matches PHP)

    results
        .into_iter()
        .map(|result| match result {
            HashResult::InvalidFormat { input } => CrackResult {
                hash: input,
                matches: Vec::new(),
                format_error: true,
            },
            HashResult::Lookup {
                queried_hash,
                matches,
            } => CrackResult {
                hash: queried_hash,
                matches: matches
                    .iter()
                    .map(|m| {
                        let lm = &m.lookup_match;
                        CrackMatch {
                            plaintext: lm.plaintext_lossy().into_owned(),
                            algorithm_name: lm.algorithm().name().to_string(),
                            is_full_match: lm.is_full(),
                            full_hash: if lm.is_full() {
                                None
                            } else {
                                Some(hex::encode(lm.recomputed_hash()))
                            },
                        }
                    })
                    .collect(),
                format_error: false,
            },
        })
        .collect()
}

