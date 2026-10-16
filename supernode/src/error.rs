// SPDX-License-Identifier: MIT
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("the data for key `{0}` is not available")]
    NotFound(String),
    #[error("ip assign error")]
    IpAssign,
}
