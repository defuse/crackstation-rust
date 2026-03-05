//! PHPCount - Privacy-preserving hit counter for CrackStation
//!
//! Tracks page hits without storing IP addresses directly.
//! Uses SHA256(pageID + IP) to track unique visits.
//!
//! Uses cshits/csnodupes tables (CrackStation-specific table names).

use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use std::time::{SystemTime, UNIX_EPOCH};

/// How long to remember a hit for unique tracking (30 days)
const HIT_OLD_AFTER_SECONDS: i64 = 2592000;

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
}

impl PhpCountService {
    /// Create a new PHPCount service with the given database pool
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
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

    /// Generate privacy-preserving hash of page + IP
    fn id_hash(page_id: &str, client_ip: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(page_id.as_bytes());
        hasher.update(client_ip.as_bytes());
        hex::encode(hasher.finalize())
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
        let ids_hash = Self::id_hash(page_id, client_ip);

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
        let ids_hash = Self::id_hash(page_id, client_ip);
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

    /// Remove old entries from csnodupes table
    async fn cleanup(&self) -> Result<(), sqlx::Error> {
        let cutoff = Self::now() - HIT_OLD_AFTER_SECONDS;

        sqlx::query("DELETE FROM csnodupes WHERE time < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
