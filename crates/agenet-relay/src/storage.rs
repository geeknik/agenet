use agenet_object::Object;
use agenet_types::{AgenetError, ObjectHash};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::sync::Arc;

/// Append-only object storage backed by SQLite.
#[derive(Clone)]
pub struct ObjectStore {
    pool: Arc<SqlitePool>,
}

impl ObjectStore {
    /// Open or create the database.
    pub async fn open(db_path: &str) -> Result<Self, AgenetError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect(&format!("sqlite:{db_path}?mode=rwc"))
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        let store = Self {
            pool: Arc::new(pool),
        };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), AgenetError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS objects (
                hash TEXT PRIMARY KEY,
                schema TEXT NOT NULL,
                author TEXT NOT NULL,
                topic TEXT,
                timestamp INTEGER NOT NULL,
                raw_json TEXT NOT NULL
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS topic_log (
                topic TEXT NOT NULL,
                seq INTEGER NOT NULL,
                object_hash TEXT NOT NULL,
                PRIMARY KEY (topic, seq)
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_objects_schema ON objects(schema)")
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_objects_author ON objects(author)")
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_objects_topic ON objects(topic)")
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_objects_timestamp ON objects(timestamp)")
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Tag index table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS object_tags (
                object_hash TEXT NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (object_hash, tag)
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_object_tags_tag ON object_tags(tag)")
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Compaction snapshots
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS compaction_snapshots (
                topic TEXT NOT NULL,
                snapshot_seq INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                object_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (topic, snapshot_seq)
            )",
        )
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Store an object. Returns its content hash. Idempotent (duplicate = no-op).
    pub async fn put(&self, object: &Object) -> Result<ObjectHash, AgenetError> {
        let hash = object.hash();
        let hash_hex = hash.to_hex();
        let raw_json =
            serde_json::to_string(object).map_err(|e| AgenetError::Serialization(e.to_string()))?;
        let schema = object.schema.to_string();
        let author = object.author.to_hex();
        let topic = object.topic.as_deref().unwrap_or("");
        let timestamp = object.timestamp;

        // Insert object (ignore if duplicate)
        sqlx::query(
            "INSERT OR IGNORE INTO objects (hash, schema, author, topic, timestamp, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&hash_hex)
        .bind(&schema)
        .bind(&author)
        .bind(topic)
        .bind(timestamp)
        .bind(&raw_json)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Index tags
        for tag in &object.tags {
            sqlx::query("INSERT OR IGNORE INTO object_tags (object_hash, tag) VALUES (?, ?)")
                .bind(&hash_hex)
                .bind(tag)
                .execute(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;
        }

        // Append to topic log if topic is set
        if let Some(ref topic_id) = object.topic {
            let next_seq: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM topic_log WHERE topic = ?",
            )
            .bind(topic_id)
            .fetch_one(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

            sqlx::query("INSERT OR IGNORE INTO topic_log (topic, seq, object_hash) VALUES (?, ?, ?)")
                .bind(topic_id)
                .bind(next_seq)
                .bind(&hash_hex)
                .execute(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;
        }

        Ok(hash)
    }

    /// Retrieve an object by its content hash.
    pub async fn get(&self, hash: &ObjectHash) -> Result<Object, AgenetError> {
        let hash_hex = hash.to_hex();
        let row: Option<(String,)> =
            sqlx::query_as("SELECT raw_json FROM objects WHERE hash = ?")
                .bind(&hash_hex)
                .fetch_optional(self.pool.as_ref())
                .await
                .map_err(|e| AgenetError::Storage(e.to_string()))?;

        match row {
            Some((raw_json,)) => {
                serde_json::from_str(&raw_json).map_err(|e| AgenetError::Serialization(e.to_string()))
            }
            None => Err(AgenetError::NotFound(hash_hex)),
        }
    }

    /// Query object hashes by tag.
    pub async fn by_tag(&self, tag: &str, limit: i64) -> Result<Vec<String>, AgenetError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT object_hash FROM object_tags WHERE tag = ? LIMIT ?",
        )
        .bind(tag)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;
        Ok(rows.into_iter().map(|(h,)| h).collect())
    }

    /// Compact a topic log: record a snapshot and prune old entries.
    ///
    /// Keeps entries after `up_to_seq`, deletes older ones, and records a snapshot
    /// with the Merkle root at that point. Returns the number of pruned entries.
    pub async fn compact_topic(
        &self,
        topic: &str,
        up_to_seq: i64,
        merkle_root: &str,
    ) -> Result<CompactionResult, AgenetError> {
        // Count entries that will be compacted
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM topic_log WHERE topic = ? AND seq <= ?",
        )
        .bind(topic)
        .bind(up_to_seq)
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        if count == 0 {
            return Ok(CompactionResult {
                pruned_entries: 0,
                snapshot_seq: up_to_seq,
            });
        }

        let now = chrono::Utc::now().timestamp();

        // Record snapshot
        sqlx::query(
            "INSERT OR REPLACE INTO compaction_snapshots (topic, snapshot_seq, merkle_root, object_count, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(topic)
        .bind(up_to_seq)
        .bind(merkle_root)
        .bind(count)
        .bind(now)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        // Delete compacted log entries
        sqlx::query("DELETE FROM topic_log WHERE topic = ? AND seq <= ?")
            .bind(topic)
            .bind(up_to_seq)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(CompactionResult {
            pruned_entries: count,
            snapshot_seq: up_to_seq,
        })
    }

    /// Get the latest compaction snapshot for a topic.
    pub async fn latest_snapshot(
        &self,
        topic: &str,
    ) -> Result<Option<CompactionSnapshot>, AgenetError> {
        let row: Option<(String, i64, String, i64, i64)> = sqlx::query_as(
            "SELECT topic, snapshot_seq, merkle_root, object_count, created_at
             FROM compaction_snapshots WHERE topic = ? ORDER BY snapshot_seq DESC LIMIT 1",
        )
        .bind(topic)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(row.map(
            |(topic, snapshot_seq, merkle_root, object_count, created_at)| CompactionSnapshot {
                topic,
                snapshot_seq,
                merkle_root,
                object_count,
                created_at,
            },
        ))
    }

    /// List object hashes in a topic log, paginated by cursor (sequence number).
    pub async fn topic_log(
        &self,
        topic: &str,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, String)>, AgenetError> {
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT seq, object_hash FROM topic_log WHERE topic = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
        )
        .bind(topic)
        .bind(after_seq)
        .bind(limit)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| AgenetError::Storage(e.to_string()))?;

        Ok(rows)
    }
}

/// Result of a compaction operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactionResult {
    pub pruned_entries: i64,
    pub snapshot_seq: i64,
}

/// A recorded compaction snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactionSnapshot {
    pub topic: String,
    pub snapshot_seq: i64,
    pub merkle_root: String,
    pub object_count: i64,
    pub created_at: i64,
}
