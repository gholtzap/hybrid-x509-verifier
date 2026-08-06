pub mod adapters;
pub mod analysis;
pub mod corpus;
pub mod input;
pub mod model;
pub mod mutation;
pub mod ocsp;
pub mod oracle;
pub mod pem;
pub mod process;

pub use model::*;
pub use oracle::{OracleError, evaluate};

#[cfg(test)]
pub(crate) fn adapter_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
