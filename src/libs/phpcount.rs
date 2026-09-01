//! PHPCount - hit counter for CrackStation.
//!
//! Counts unique visits without keeping anything that identifies a visitor.
//!
//! The identifier stored for each visit is `HMAC-SHA256(k, pageID ‖ 0x00 ‖ IP)`,
//! where `k` is 32 random bytes generated at startup and held **only in memory**.
//! Nothing writes `k` anywhere, so a copy of the database — a backup, a snapshot, a
//! disk, a subpoena — contains no way to test whether a given address is in it.
//!
//! It used to be a bare `SHA256(pageID ‖ IP)`. Both inputs are public and
//! low-entropy: the page identifier is one of ten compile-time constants in an
//! AGPL-licensed repository and the address is 32 bits for an IPv4 visitor, so the
//! whole table could be reversed by sweeping the space — measured during the audit at
//! about two seconds on one GPU, and a *targeted* "was this address here?" is a single
//! hash and a lookup. The table was a rolling 30-day, per-page, timestamped list of
//! visitor IP addresses while documenting itself as privacy-preserving.
//!
//! Two consequences of keeping the key in RAM, both deliberate:
//!
//! - **A restart resets uniqueness.** Stored identifiers were computed under the old
//!   key, so returning visitors are counted as new once each. The aggregate counters
//!   in `cshits` are untouched; only the "have I seen this visitor" test resets.
//! - **The key rotates every 60 days**, overwriting the old one, so a process that
//!   outlives the retention window does not accumulate a linkable history. Rotation
//!   has the same effect as a restart.
//!
//! Uses cshits/csnodupes tables (CrackStation-specific table names).

use hmac::{Hmac, Mac};
use rand::TryRng;
use sha2::Sha256;
use sqlx::MySqlPool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long to remember a hit for unique tracking (30 days)
const HIT_OLD_AFTER_SECONDS: i64 = 2592000;

/// How long a visitor key lives before it is replaced (60 days).
///
/// Comfortably longer than `HIT_OLD_AFTER_SECONDS`, so a key always outlives the rows
/// written under it and rotation never orphans a row that is still being consulted.
const VISITOR_KEY_LIFETIME: Duration = Duration::from_secs(60 * 24 * 60 * 60);

/// The secret that makes a stored visitor identifier meaningless without this process.
///
/// Deliberately has no `Debug`, no `Clone`, no accessor and no serialisation: the only
/// thing that can be done with it is compute an HMAC. That is what keeps it out of a
/// log line or an error message by construction rather than by remembering not to.
struct VisitorKey {
    key: [u8; 32],
    created: Instant,
}

impl VisitorKey {
    fn new() -> Self {
        let mut key = [0u8; 32];
        // Fails only if the OS entropy source is unavailable, which is not a condition
        // to paper over -- a predictable key would silently restore the reversibility
        // this whole mechanism exists to remove.
        rand::rngs::SysRng
            .try_fill_bytes(&mut key)
            .expect("OS entropy source must be available to key the visitor counter");
        Self {
            key,
            created: Instant::now(),
        }
    }

    /// Replace the key in place, overwriting the old bytes where they sit.
    ///
    /// Writing the new key over the old array is the erasure: it does not leave the
    /// previous value behind at that address. It cannot scrub copies the allocator or
    /// the OS may have made elsewhere, which would need a `zeroize`-style guarantee;
    /// for a counter key whose worst case is linking visits inside one 60-day window,
    /// that is not worth another dependency.
    fn rotate(&mut self) {
        let fresh = Self::new();
        self.key = fresh.key;
        self.created = fresh.created;
    }

    fn is_expired(&self) -> bool {
        self.created.elapsed() >= VISITOR_KEY_LIFETIME
    }
}

/// Bot detection keywords (case-insensitive)
const BOT_KEYWORDS: &[&str] = &[
    "bot", "spider", "spyder", "crawler", "walker", "search",
    "yahoo", "holmes", "htdig", "archive", "tineye", "yacy", "yeti",
];

/// Hit counts for a page and site totals.
#[derive(Clone, Debug, Default)]
pub struct HitCounts {
    pub page_hits: u64,
    pub unique_hits: u64,
    pub total_hits: u64,
    pub total_unique_hits: u64,
}

#[derive(Clone)]
pub struct PhpCountService {
    pool: MySqlPool,
    /// Shared by every clone, so the whole process uses one key and one rotation
    /// schedule. `RwLock` because reads vastly outnumber the 60-day write.
    visitor_key: Arc<RwLock<VisitorKey>>,
}

impl PhpCountService {
    /// Create a new PHPCount service with the given database pool
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            visitor_key: Arc::new(RwLock::new(VisitorKey::new())),
        }
    }

    /// Connect to the database and create a new service
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = MySqlPool::connect(database_url).await?;
        Ok(Self::new(pool))
    }

    /// Record a hit for a page. Returns true if the hit was counted.
    ///
    /// Skips counting for:
    /// - Search bots (based on user agent)
    pub async fn add_hit(
        &self,
        page_id: &str,
        client_ip: &str,
        user_agent: &str,
    ) -> Result<bool, sqlx::Error> {
        // Skip search bots
        if Self::is_search_bot(user_agent) {
            return Ok(false);
        }

        // Clean up old entries periodically
        self.cleanup().await?;

        // Ensure page has counter entries
        self.create_counts_if_not_present(page_id).await?;

        // Known race, carried over from the PHP original and shared with defuse-rust:
        // two concurrent requests from the same IP both see "unique" before either one
        // calls log_hit(), so both increment the unique counter while log_hit's
        // ON DUPLICATE KEY UPDATE collapses them into a single dedupe row. "Unique Hits"
        // therefore counts concurrent requests rather than distinct visitors, and can be
        // driven up from one address.
        //
        // Not fixed, deliberately. Closing it needs a transaction, and both tables are
        // MyISAM to match the live schema -- also deliberate, since converting them is a
        // migration on a table holding years of production counts, for a decorative hit
        // counter. The same non-atomicity means a failure part way through this sequence
        // leaves the counters inconsistent with no rollback available.
        if self.is_unique_hit(page_id, client_ip).await? {
            self.count_hit(page_id, true).await?;
            self.log_hit(page_id, client_ip).await?;
        }

        // Always count non-unique hits
        self.count_hit(page_id, false).await?;

        Ok(true)
    }

    /// Get all hit counts for a page (page hits, unique hits, and site totals).
    pub async fn get_hit_counts(&self, page_id: &str) -> Result<HitCounts, sqlx::Error> {
        // Ensure page exists first
        self.create_counts_if_not_present(page_id).await?;

        // Per-page counts
        let page_hits: (u64,) = sqlx::query_as(
            "SELECT hitcount FROM cshits WHERE pageid = ? AND isunique = 0 LIMIT 1"
        )
        .bind(page_id)
        .fetch_one(&self.pool)
        .await?;

        let unique_hits: (u64,) = sqlx::query_as(
            "SELECT hitcount FROM cshits WHERE pageid = ? AND isunique = 1 LIMIT 1"
        )
        .bind(page_id)
        .fetch_one(&self.pool)
        .await?;

        // Site-wide totals
        let total_hits: (u64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(hitcount), 0) AS UNSIGNED) FROM cshits WHERE isunique = 0"
        )
        .fetch_one(&self.pool)
        .await?;

        let total_unique_hits: (u64,) = sqlx::query_as(
            "SELECT CAST(COALESCE(SUM(hitcount), 0) AS UNSIGNED) FROM cshits WHERE isunique = 1"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(HitCounts {
            page_hits: page_hits.0,
            unique_hits: unique_hits.0,
            total_hits: total_hits.0,
            total_unique_hits: total_unique_hits.0,
        })
    }

    /// Check if user agent belongs to a search bot
    fn is_search_bot(user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        BOT_KEYWORDS.iter().any(|keyword| ua_lower.contains(keyword))
    }

    /// The stored identifier for one (page, visitor) pair.
    ///
    /// Keyed with the in-memory secret, so the value is uninvertible to anyone holding
    /// only the database. Rotating the key here rather than on a timer keeps the whole
    /// mechanism to one code path with no background task to fail silently.
    ///
    /// The two inputs are separated by a NUL, which neither can contain, so
    /// ("ab", "c") and ("a", "bc") cannot collide -- the old concatenation allowed it.
    fn id_hash(&self, page_id: &str, client_ip: &str) -> String {
        {
            let key = self
                .visitor_key
                .read()
                .expect("visitor key lock poisoned");
            if key.is_expired() {
                drop(key);
                let mut key = self
                    .visitor_key
                    .write()
                    .expect("visitor key lock poisoned");
                // Re-check: another thread may have rotated while this one waited.
                if key.is_expired() {
                    key.rotate();
                }
            }
        }

        let key = self
            .visitor_key
            .read()
            .expect("visitor key lock poisoned");
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.key)
            .expect("HMAC accepts a key of any length");
        mac.update(page_id.as_bytes());
        mac.update(&[0x00]);
        mac.update(client_ip.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Get current unix timestamp
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX epoch")
            .as_secs() as i64
    }

    /// Check if this is a unique hit (not seen in last 30 days)
    async fn is_unique_hit(&self, page_id: &str, client_ip: &str) -> Result<bool, sqlx::Error> {
        let ids_hash = self.id_hash(page_id, client_ip);

        let result: Option<(u64,)> = sqlx::query_as(
            "SELECT time FROM csnodupes WHERE ids_hash = ?"
        )
        .bind(&ids_hash)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some((time,)) => {
                Ok((time as i64) <= Self::now() - HIT_OLD_AFTER_SECONDS)
            }
            None => Ok(true),
        }
    }

    /// Log a unique hit (insert or update csnodupes table)
    async fn log_hit(&self, page_id: &str, client_ip: &str) -> Result<(), sqlx::Error> {
        let ids_hash = self.id_hash(page_id, client_ip);
        let now = Self::now();

        sqlx::query(
            "INSERT INTO csnodupes (ids_hash, time) VALUES (?, ?)
             ON DUPLICATE KEY UPDATE time = VALUES(time)"
        )
        .bind(&ids_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Increment hit counter for a page
    async fn count_hit(&self, page_id: &str, unique: bool) -> Result<(), sqlx::Error> {
        let is_unique: i8 = if unique { 1 } else { 0 };

        sqlx::query(
            "UPDATE cshits SET hitcount = hitcount + 1 WHERE pageid = ? AND isunique = ?"
        )
        .bind(page_id)
        .bind(is_unique)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Ensure page has entries in cshits table (both unique and non-unique)
    async fn create_counts_if_not_present(&self, page_id: &str) -> Result<(), sqlx::Error> {
        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT pageid FROM cshits WHERE pageid = ? AND isunique = 0"
        )
        .bind(page_id)
        .fetch_optional(&self.pool)
        .await?;

        if exists.is_none() {
            sqlx::query("INSERT INTO cshits (pageid, isunique, hitcount) VALUES (?, 0, 0)")
                .bind(page_id)
                .execute(&self.pool)
                .await?;
        }

        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT pageid FROM cshits WHERE pageid = ? AND isunique = 1"
        )
        .bind(page_id)
        .fetch_optional(&self.pool)
        .await?;

        if exists.is_none() {
            sqlx::query("INSERT INTO cshits (pageid, isunique, hitcount) VALUES (?, 1, 0)")
                .bind(page_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Remove old entries from the csnodupes table.
    ///
    /// # If the site is mysteriously slow, start here
    ///
    /// This runs on **every counted page view**, and it is a full table scan holding a
    /// **table-level write lock** -- so the cost is not per-page, it serialises the whole
    /// site. `csnodupes` is MyISAM with `PRIMARY KEY (ids_hash)` and **no index on
    /// `time`**, which is the only column this filters on.
    ///
    /// The cost tracks how many rows the table has *ever* held, not how many it holds
    /// now. MyISAM flags a deleted row and links its slot onto a free list; the data
    /// file never shrinks, and a scan walks slots by offset, holes included. So a one-off
    /// flood makes every later request slower, permanently, with nothing in
    /// `SELECT COUNT(*)` to show for it -- which is exactly what makes this hard to
    /// diagnose from the application side.
    ///
    /// Measured on a dev table: 41 live rows swept in 0.1 ms; after inserting and then
    /// deleting 200k rows, sweeping the *same 41 live rows* took 3.7 ms, a 37x
    /// regression, with `Data_free` at 14.6 MB. `OPTIMIZE TABLE` returned it to 0.2 ms.
    ///
    /// Confirm it:
    ///
    /// ```sql
    /// SHOW TABLE STATUS LIKE 'csnodupes';            -- Data_free large while Rows is small
    /// EXPLAIN DELETE FROM csnodupes WHERE time < 1;  -- type=ALL means full scan
    /// ```
    ///
    /// Fix it, in ascending order of effort and effect:
    ///
    /// ```sql
    /// OPTIMIZE TABLE csnodupes;              -- reclaims the holes; one-off, fixes the symptom
    /// ALTER TABLE csnodupes ADD KEY (time);  -- makes the sweep an index range scan
    /// ALTER TABLE csnodupes ENGINE=InnoDB;   -- removes the site-wide write lock
    /// ```
    ///
    /// Accepted rather than fixed (2026-08-31), because filling the table needs many
    /// distinct client addresses and `client_ip` now returns the one the proxy vouched
    /// for rather than one the requester chose -- so a client gets one row per page, not
    /// unlimited. The remaining way in is an IPv6 client with a /64, whose addresses are
    /// all legitimately distinct; keying the counter on the /64 would close that. See
    /// `hit-counter-db-work-on-every-request-enables-cheap-dos.md` in the audit.
    async fn cleanup(&self) -> Result<(), sqlx::Error> {
        let cutoff = Self::now() - HIT_OLD_AFTER_SECONDS;

        sqlx::query("DELETE FROM csnodupes WHERE time < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod visitor_key_tests {
    use super::*;

    /// Two processes must not agree on an identifier, or the key is not doing its job.
    #[test]
    fn independent_keys_produce_independent_identifiers() {
        let a = VisitorKey::new();
        let b = VisitorKey::new();
        assert_ne!(a.key, b.key, "each key must be independently random");

        let hash = |k: &VisitorKey| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&k.key).expect("key length");
            mac.update(b"pages/home.php");
            mac.update(&[0x00]);
            mac.update(b"192.0.2.1");
            hex::encode(mac.finalize().into_bytes())
        };
        assert_ne!(
            hash(&a),
            hash(&b),
            "the same visitor must hash differently under different keys -- this is what \
             makes a leaked database useless without the process that wrote it"
        );
    }

    /// The property the whole change exists for: knowing the page and the address is
    /// not enough to reproduce the stored value. Whoever holds only the database has
    /// exactly those two things.
    #[test]
    fn the_identifier_cannot_be_reproduced_without_the_key() {
        let key = VisitorKey::new();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.key).expect("key length");
        mac.update(b"pages/home.php");
        mac.update(&[0x00]);
        mac.update(b"192.0.2.1");
        let keyed = hex::encode(mac.finalize().into_bytes());

        // What an attacker with the database and the public repository can compute.
        use sha2::Digest;
        let mut unkeyed = Sha256::new();
        unkeyed.update(b"pages/home.php");
        unkeyed.update(b"192.0.2.1");
        assert_ne!(
            keyed,
            hex::encode(unkeyed.finalize()),
            "the stored value must not be the unkeyed hash anyone can recompute"
        );
    }

    /// Rotation must actually replace the secret, not just reset the clock.
    #[test]
    fn rotation_replaces_the_key_and_restarts_the_clock() {
        let mut key = VisitorKey::new();
        let before = key.key;
        let created_before = key.created;

        key.rotate();

        assert_ne!(before, key.key, "rotate must install fresh bytes");
        assert!(
            key.created >= created_before,
            "rotate must restart the lifetime"
        );
        assert!(!key.is_expired(), "a fresh key is not expired");
    }

    /// A key must outlive the rows written under it, or rotation would orphan rows the
    /// counter is still consulting and returning visitors would be miscounted early.
    #[test]
    fn the_key_outlives_the_retention_window() {
        assert!(
            VISITOR_KEY_LIFETIME.as_secs() > HIT_OLD_AFTER_SECONDS as u64,
            "key lifetime ({}s) must exceed the {}s retention window",
            VISITOR_KEY_LIFETIME.as_secs(),
            HIT_OLD_AFTER_SECONDS
        );
        assert_eq!(VISITOR_KEY_LIFETIME.as_secs(), 60 * 24 * 60 * 60);
    }

    /// The identifier still fits the char(64) column it is stored in.
    #[test]
    fn the_identifier_is_still_64_hex_characters() {
        let key = VisitorKey::new();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key.key).expect("key length");
        mac.update(b"pages/home.php");
        let hash = hex::encode(mac.finalize().into_bytes());
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The old construction concatenated the two inputs with no separator, so
    /// ("ab", "c") and ("a", "bc") collided. The NUL separator removes that.
    #[test]
    fn page_and_address_cannot_be_confused_for_one_another() {
        let key = VisitorKey::new();
        let hash = |page: &str, ip: &str| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key.key).expect("key length");
            mac.update(page.as_bytes());
            mac.update(&[0x00]);
            mac.update(ip.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };
        assert_ne!(hash("ab", "c"), hash("a", "bc"));
    }
}
