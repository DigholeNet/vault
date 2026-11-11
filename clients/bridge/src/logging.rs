// SPDX-License-Identifier: MIT
//! Shared file-log operations exposed to the platform's asynchronous wrappers.

use vault_core::logger::shared;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SharedLogError {
    #[error("shared log I/O failed: {0}")]
    Io(String),
}

impl From<std::io::Error> for SharedLogError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

#[uniffi::export]
pub fn append_shared_log(
    level: String,
    source: String,
    message: String,
    timestamp_ms: Option<u64>,
) {
    shared::append_record(&level, &source, &message, timestamp_ms);
}

#[uniffi::export]
pub fn read_shared_logs(legacy_timezone_offset_seconds: i32) -> Result<String, SharedLogError> {
    shared::read(legacy_timezone_offset_seconds).map_err(Into::into)
}

#[uniffi::export]
pub fn clear_shared_logs() -> Result<(), SharedLogError> {
    shared::clear().map_err(Into::into)
}

#[uniffi::export]
pub fn rotate_shared_log_for_new_session() -> Result<(), SharedLogError> {
    shared::rotate_for_new_session().map_err(Into::into)
}

#[uniffi::export]
pub fn merge_shared_logs(parts: Vec<String>, legacy_timezone_offset_seconds: i32) -> String {
    shared::merge_chronologically(&parts, legacy_timezone_offset_seconds)
}
