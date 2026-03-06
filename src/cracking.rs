//! Hash cracking logic — PreimageOracle setup and result types.

use std::path::Path;

use preimage::hashing::{
    Lm, Ntlm, MySql41, Md5Md5, Md5, Sha1, Md2, Md4,
    Sha256, Sha224, Sha384, Sha512, Whirlpool, Ripemd160, QubesV31,
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

