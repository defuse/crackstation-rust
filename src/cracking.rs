//! Hash cracking logic — PreimageOracle setup and result types.

use std::path::Path;

use preimage::{
    HashAlgorithm, HashResult, PreimageOracle,
    LM, NTLM, MYSQL41, MD5MD5, MD5, SHA1, MD2, MD4,
    SHA256, SHA224, SHA384, SHA512, WHIRLPOOL, RIPEMD160, QUBESV31,
};

/// A cracked hash result for one input hash.
pub struct CrackResult {
    pub hash: String,
    pub matches: Vec<CrackMatch>,
    /// How many matches existed for this hash across every table consulted, whether or
    /// not they were kept. Larger than `matches.len()` when MAX_MATCHES_PER_HASH bit.
    pub total_matches: usize,
    /// True when the input is not a valid hash format (non-hex, odd-length, or too short).
    pub format_error: bool,
}

impl CrackResult {
    /// How many matches exist that are not being shown.
    pub fn hidden_matches(&self) -> usize {
        self.total_matches.saturating_sub(self.matches.len())
    }

    /// Whether the results table should say it is showing a subset.
    pub fn is_truncated(&self) -> bool {
        self.hidden_matches() > 0
    }
}

impl CrackMatch {
    /// The plaintext as HTML that displays identically to the text itself.
    ///
    /// A table cell is a whitespace-collapsing context, so a password of `"a  b"`,
    /// `" hunter2"` or `"pass\t"` renders as something the user cannot copy back --
    /// and cannot distinguish from a different password. This runs the same escaper
    /// defuse.ca uses, which converts the runs HTML would eat into `&nbsp;` while
    /// escaping everything with meaning in HTML first.
    ///
    /// The result is already escaped, so the template must render it with `|safe`.
    /// That is only sound because `escape_text` escapes before it introduces any
    /// markup of its own — see its tests.
    pub fn plaintext_html(&self) -> String {
        let escaped = crate::libs::html_escape::escape_text(&self.plaintext, false, 8);

        // `escape_text` protects a trailing space only when a line ending follows it,
        // which is what its source contexts need. Here the string ends at `</td>`, and
        // a space in that position collapses just as surely -- and a trailing space is
        // exactly the kind of password character this whole change exists to preserve.
        match escaped.strip_suffix(' ') {
            Some(head) => format!("{head}&nbsp;"),
            None => escaped,
        }
    }
}

/// A single match found for a hash.
pub struct CrackMatch {
    pub plaintext: String,
    pub algorithm_name: String,
    /// `None` when the word hashes to exactly what was submitted. `Some` when only a
    /// leading run agreed — see `NearMiss`.
    ///
    /// This is the only record of which kind of match this is, so the row colour and
    /// the digest shown cannot disagree about it.
    pub near_miss: Option<NearMiss>,
}

/// The digest a near-miss word really produces, split where it stops agreeing with the
/// hash that was submitted.
///
/// A yellow row says "this word's hash starts the same as yours". Without the digest
/// itself that claim is unfalsifiable — the reader cannot see how much matched, or what
/// the word actually hashes to. Both halves are carried as plain text so the template
/// escapes them like anything else; the highlight is a `<span>` the template adds
/// around the first, never markup built here.
pub struct NearMiss {
    /// The leading part of the real digest that the submitted hash got right. Always at
    /// least the 8-byte index prefix, which is why the entry was a candidate at all.
    pub matched: String,
    /// The remainder of the real digest, which the submitted hash did not have.
    pub rest: String,
}

impl NearMiss {
    /// Split `actual` at the point where it stops agreeing with `submitted`.
    ///
    /// The comparison is case-insensitive: `hex::encode` always produces lowercase, and
    /// a visitor may paste an uppercase hash, so comparing directly would report that
    /// nothing matched about a hash that was entirely right. The digest is shown as
    /// produced, in lowercase, rather than echoing the submitted casing — it is the
    /// dictionary word's hash being displayed, not the visitor's string.
    fn new(submitted: &str, actual: &str) -> Self {
        let matched_len = submitted
            .chars()
            .zip(actual.chars())
            .take_while(|(s, a)| s.eq_ignore_ascii_case(a))
            .count();

        Self {
            matched: actual[..matched_len].to_string(),
            rest: actual[matched_len..].to_string(),
        }
    }
}

impl CrackMatch {
    /// Whether the word hashes to exactly what was submitted.
    pub fn is_full_match(&self) -> bool {
        self.near_miss.is_none()
    }

    /// The leading part of the real digest that the submitted hash got right.
    ///
    /// # Panics
    ///
    /// Panics when called on a full match, where there is no second digest to show.
    /// Only the partial-row branch of the template may call this.
    pub fn matched_prefix(&self) -> &str {
        &self
            .near_miss
            .as_ref()
            .expect("matched_prefix is only meaningful for a near miss")
            .matched
    }

    /// The remainder of the real digest, which the submitted hash did not have.
    ///
    /// # Panics
    ///
    /// Panics when called on a full match — see `matched_prefix`.
    pub fn unmatched_rest(&self) -> &str {
        &self
            .near_miss
            .as_ref()
            .expect("unmatched_rest is only meaningful for a near miss")
            .rest
    }
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

/// Most matches shown for any one submitted hash.
///
/// A collision block holds however many words share a hash prefix, and for a query
/// shorter than the digest every one of them is a near miss by construction — so an
/// uncapped lookup could return the whole block, allocate a display record per entry
/// and render a table row per entry. The form already caps submissions at 20 hashes,
/// so this bounds one request at 20 x 20 rows regardless of what was asked for.
///
/// This caps what is *shown*, not what is searched: every block is still walked, so the
/// count of what is being withheld is exact, and the exact match is never the thing
/// dropped (see `PreimageOracle::crack_with_limit`).
pub const MAX_MATCHES_PER_HASH: usize = 20;

/// Crack a list of hashes using the oracle.
///
/// Returns one CrackResult per input hash, in the same order.
/// Invalid hash formats (non-hex, odd-length, too short) are returned with
/// `format_error: true` — validation is handled by the oracle.
pub fn crack_hashes(oracle: &PreimageOracle, hashes: &[String]) -> Vec<CrackResult> {
    let hash_refs: Vec<&str> = hashes.iter().map(|h| h.as_str()).collect();
    let results = oracle
        .crack_with_limit(&hash_refs, true, MAX_MATCHES_PER_HASH) // early_exit = true (matches PHP)
        .expect("oracle lookup failed — index or dictionary file may be corrupted or missing");

    results
        .into_iter()
        .map(|result| match result {
            HashResult::InvalidFormat { input } => CrackResult {
                hash: input,
                matches: Vec::new(),
                total_matches: 0,
                format_error: true,
            },
            HashResult::Lookup {
                queried_hash,
                matches,
                total_matches,
            } => {
                let matches = matches
                    .iter()
                    .map(|m| {
                        let lm = &m.lookup_match;
                        CrackMatch {
                            plaintext: lm.plaintext_lossy().into_owned(),
                            algorithm_name: lm.algorithm().name().to_string(),
                            near_miss: if lm.is_full() {
                                None
                            } else {
                                Some(NearMiss::new(
                                    &queried_hash,
                                    &hex::encode(lm.recomputed_hash()),
                                ))
                            },
                        }
                    })
                    .collect();

                CrackResult {
                    hash: queried_hash,
                    total_matches,
                    matches,
                    format_error: false,
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use preimage::{IndexFile, Lm};
    use std::io::Write;
    use tempfile::TempDir;

    /// Build an oracle over a wordlist whose entries all land in one collision block.
    ///
    /// LM's index prefix is DES of the uppercased first seven characters, so every word
    /// starting "PASSWOR" collides while hashing to a different full digest. That gives
    /// a single oversized block containing exactly one exact match and many near
    /// misses -- the shape a short-hash query produces against the production tables,
    /// and the one this limit exists for.
    fn oracle_with_collision_block(
        count: usize,
        answer_at: usize,
    ) -> (PreimageOracle, String, TempDir) {
        let dir = TempDir::new().expect("temp dir");
        let words_path = dir.path().join("words.lst");
        let mut words = std::fs::File::create(&words_path).expect("create wordlist");
        let mut answer = String::new();
        for i in 0..count {
            let word = format!("PASSWORD{i:03}");
            if i == answer_at {
                answer = word.clone();
            }
            writeln!(words, "{word}").expect("write");
        }
        words.flush().expect("flush");

        let index_path = dir.path().join("lm.idx");
        let index = IndexFile::build(&Lm, &words_path, &index_path, None).expect("build");
        index.sort(1024 * 1024, None).expect("sort");

        let mut oracle = PreimageOracle::new();
        oracle
            .register("lm", LM, &index_path, &words_path)
            .expect("register");

        (oracle, answer, dir)
    }

    fn lm_hex(word: &str) -> String {
        hex::encode(Lm.hash(word.as_bytes()).expect("lm hash"))
    }

    /// The limit reaches the oracle, and the count needed to report it survives.
    #[test]
    fn a_large_collision_block_is_capped_at_the_display_limit() {
        let block = MAX_MATCHES_PER_HASH * 5;
        let (oracle, answer, _dir) = oracle_with_collision_block(block, 0);

        let results = crack_hashes(&oracle, &[lm_hex(&answer)]);
        assert_eq!(results.len(), 1);
        let result = &results[0];

        assert_eq!(
            result.matches.len(),
            MAX_MATCHES_PER_HASH,
            "a block of {block} must be cut to the display limit"
        );
        assert_eq!(result.total_matches, block, "the real count must survive");
        assert!(result.is_truncated());
        assert_eq!(result.hidden_matches(), block - MAX_MATCHES_PER_HASH);
    }

    /// The whole point of the cap is bounding one request, so check the arithmetic the
    /// form's own 20-hash cap combines with.
    #[test]
    fn a_full_submission_is_bounded_at_twenty_by_twenty() {
        let (oracle, answer, _dir) = oracle_with_collision_block(200, 0);
        let hashes = vec![lm_hex(&answer); 20];

        let results = crack_hashes(&oracle, &hashes);
        let rendered: usize = results.iter().map(|r| r.matches.len()).sum();

        assert_eq!(results.len(), 20);
        assert_eq!(
            rendered,
            20 * MAX_MATCHES_PER_HASH,
            "20 hashes x {MAX_MATCHES_PER_HASH} matches is the ceiling for one request"
        );
    }

    /// The cap must never be the reason a crackable hash reports nothing.
    #[test]
    fn the_answer_survives_even_when_it_sits_past_the_limit() {
        let (oracle, answer, _dir) = oracle_with_collision_block(100, 90);

        let results = crack_hashes(&oracle, &[lm_hex(&answer)]);
        let result = &results[0];

        assert_eq!(result.matches.len(), MAX_MATCHES_PER_HASH);
        assert!(
            result.matches[0].is_full_match(),
            "the exact match must be kept, and shown first"
        );
        assert_eq!(result.matches[0].plaintext, answer);
    }

    /// The split point is where the two digests stop agreeing, which for a query
    /// shorter than the digest is the whole of what was typed.
    #[test]
    fn a_short_query_matches_all_of_what_was_submitted() {
        let actual = "d0763edaa9d9bd2a9516280e9044d885";
        let near = NearMiss::new("d0763edaa9d9bd2a", actual);

        assert_eq!(near.matched, "d0763edaa9d9bd2a");
        assert_eq!(near.rest, "9516280e9044d885");
    }

    /// A full-length query that missed agrees only as far as the index prefix, and the
    /// wrong tail the visitor supplied is not part of the digest being shown.
    #[test]
    fn a_full_length_miss_matches_only_the_index_prefix() {
        let actual = "d0763edaa9d9bd2a9516280e9044d885";
        let near = NearMiss::new("d0763edaa9d9bd2a0000000000000000", actual);

        assert_eq!(near.matched, "d0763edaa9d9bd2a");
        assert_eq!(near.rest, "9516280e9044d885");
    }

    /// Nothing pins the split to the prefix length: agreement past it is real and must
    /// be shown as matched.
    #[test]
    fn agreement_beyond_the_index_prefix_counts() {
        let actual = "d0763edaa9d9bd2a9516280e9044d885";
        let near = NearMiss::new("d0763edaa9d9bd2a95160000000000ff", actual);

        assert_eq!(near.matched, "d0763edaa9d9bd2a9516");
        assert_eq!(near.rest, "280e9044d885");
    }

    /// An uppercase submission is the same hash. Comparing it directly would report
    /// that none of it matched, on a row whose entire purpose is to say how much did.
    #[test]
    fn an_uppercase_submission_still_matches() {
        let actual = "d0763edaa9d9bd2a9516280e9044d885";
        let near = NearMiss::new("D0763EDAA9D9BD2A0000000000000000", actual);

        assert_eq!(
            near.matched, "d0763edaa9d9bd2a",
            "shown as produced, in lowercase"
        );
        assert_eq!(near.rest, "9516280e9044d885");
    }

    /// A submission longer than the digest can still select the block. Everything the
    /// digest has agreed, so there is nothing left to reveal.
    #[test]
    fn a_submission_longer_than_the_digest_leaves_no_remainder() {
        let actual = "d0763edaa9d9bd2a9516280e9044d885";
        let near = NearMiss::new(&format!("{actual}00000000"), actual);

        assert_eq!(near.matched, actual);
        assert_eq!(near.rest, "");
    }

    /// The digest shown on a near-miss row must be that word's own, not the query's,
    /// and must reassemble to exactly it.
    #[test]
    fn near_miss_rows_carry_the_words_own_digest() {
        let (oracle, answer, _dir) = oracle_with_collision_block(5, 0);
        let queried = lm_hex(&answer);

        let results = crack_hashes(&oracle, std::slice::from_ref(&queried));
        let result = &results[0];

        let near_misses: Vec<&CrackMatch> = result
            .matches
            .iter()
            .filter(|m| !m.is_full_match())
            .collect();
        assert_eq!(
            near_misses.len(),
            4,
            "one exact match and the rest of the block"
        );

        for near_miss in near_misses {
            let shown = format!(
                "{}{}",
                near_miss.matched_prefix(),
                near_miss.unmatched_rest()
            );
            assert_eq!(
                shown,
                lm_hex(&near_miss.plaintext),
                "the row must show what {:?} actually hashes to",
                near_miss.plaintext
            );
            assert_ne!(shown, queried, "a near miss does not hash to the query");
            assert_eq!(
                near_miss.matched_prefix(),
                &queried[..16],
                "the block was selected on the 8-byte index prefix, so it must agree"
            );
        }
    }

    /// A full match has no second digest, and asking for one is a template bug.
    #[test]
    #[should_panic(expected = "matched_prefix is only meaningful for a near miss")]
    fn asking_a_full_match_for_a_matched_prefix_panics() {
        let (oracle, answer, _dir) = oracle_with_collision_block(1, 0);
        let results = crack_hashes(&oracle, &[lm_hex(&answer)]);

        results[0].matches[0].matched_prefix();
    }

    /// An ordinary result set must not claim anything is hidden.
    #[test]
    fn a_small_result_set_is_not_marked_truncated() {
        let (oracle, answer, _dir) = oracle_with_collision_block(3, 0);

        let results = crack_hashes(&oracle, &[lm_hex(&answer)]);
        let result = &results[0];

        assert_eq!(result.matches.len(), 3);
        assert_eq!(result.total_matches, 3);
        assert!(!result.is_truncated());
        assert_eq!(result.hidden_matches(), 0);
    }
}
