//! The receipt/evidence spine.
//!
//! Every meaningful kernel step — boundary discovery, snapshot capture,
//! candidate proposal, lawfulness judgment, projection — appends a receipt
//! to a per-run JSONL file. Receipts are hash-chained: each record commits
//! to the previous record's hash, so any later edit, deletion, or reordering
//! breaks verification.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub timestamp: String,
    /// "boundary_discovered" | "snapshot_captured" | "candidates_proposed"
    /// | "judgment" | "projection"
    pub kind: String,
    pub payload_hash: String,
    pub prev_hash: String,
    pub hash: String,
    pub body: serde_json::Value,
}

impl Receipt {
    fn compute_hash(seq: u64, timestamp: &str, kind: &str, payload_hash: &str, prev_hash: &str) -> String {
        sha256_hex(format!("{seq}|{timestamp}|{kind}|{payload_hash}|{prev_hash}").as_bytes())
    }
}

/// Appends hash-chained receipts to `<home>/receipts/<run_id>.jsonl`.
pub struct ReceiptWriter {
    path: PathBuf,
    seq: u64,
    prev_hash: String,
}

impl ReceiptWriter {
    pub fn create(home: &Path, run_id: &str) -> Result<Self, String> {
        let dir = home.join("receipts");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        Ok(Self {
            path: dir.join(format!("{run_id}.jsonl")),
            seq: 0,
            prev_hash: GENESIS_HASH.to_string(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn emit(&mut self, kind: &str, body: serde_json::Value) -> Result<(), String> {
        let payload = serde_json::to_string(&body).map_err(|e| e.to_string())?;
        let payload_hash = sha256_hex(payload.as_bytes());
        let timestamp = chrono::Utc::now().to_rfc3339();
        let hash = Receipt::compute_hash(self.seq, &timestamp, kind, &payload_hash, &self.prev_hash);
        let receipt = Receipt {
            seq: self.seq,
            timestamp,
            kind: kind.to_string(),
            payload_hash,
            prev_hash: self.prev_hash.clone(),
            hash: hash.clone(),
            body,
        };
        let line = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot open {}: {e}", self.path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("cannot write receipt: {e}"))?;
        self.seq += 1;
        self.prev_hash = hash;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ChainReport {
    pub receipts: u64,
    pub valid: bool,
    pub first_invalid_seq: Option<u64>,
    pub detail: Option<String>,
}

/// Re-derive every hash in a receipt file and check the chain links up.
pub fn verify_chain(path: &Path) -> Result<ChainReport, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq: u64 = 0;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let receipt: Receipt = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ChainReport {
                    receipts: expected_seq,
                    valid: false,
                    first_invalid_seq: Some(expected_seq),
                    detail: Some(format!("unparseable receipt: {e}")),
                })
            }
        };
        let payload = serde_json::to_string(&receipt.body).map_err(|e| e.to_string())?;
        let payload_hash = sha256_hex(payload.as_bytes());
        let recomputed = Receipt::compute_hash(
            receipt.seq,
            &receipt.timestamp,
            &receipt.kind,
            &payload_hash,
            &receipt.prev_hash,
        );
        let problem = if receipt.seq != expected_seq {
            Some(format!("expected seq {expected_seq}, found {}", receipt.seq))
        } else if receipt.prev_hash != expected_prev {
            Some("prev_hash does not match previous receipt".to_string())
        } else if payload_hash != receipt.payload_hash {
            Some("payload_hash does not match body".to_string())
        } else if recomputed != receipt.hash {
            Some("hash does not match receipt contents".to_string())
        } else {
            None
        };
        if let Some(detail) = problem {
            return Ok(ChainReport {
                receipts: expected_seq,
                valid: false,
                first_invalid_seq: Some(receipt.seq),
                detail: Some(detail),
            });
        }
        expected_prev = receipt.hash;
        expected_seq += 1;
    }
    Ok(ChainReport {
        receipts: expected_seq,
        valid: true,
        first_invalid_seq: None,
        detail: None,
    })
}
