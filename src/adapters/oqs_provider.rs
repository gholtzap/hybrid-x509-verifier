use super::{
    AdapterExecution,
    openssl::{OpenSslContainerConfig, OpenSslError, verify_container_as},
};
use crate::VersionTrack;
use std::{path::PathBuf, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct OqsProviderConfig {
    pub docker: PathBuf,
    pub image: String,
    pub trust_store: PathBuf,
    pub intermediate: PathBuf,
    pub leaf: PathBuf,
    pub validation_time: String,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Error)]
pub enum OqsProviderError {
    #[error(transparent)]
    OpenSsl(#[from] OpenSslError),
}

pub fn verify(config: &OqsProviderConfig) -> Result<AdapterExecution, OqsProviderError> {
    Ok(verify_container_as(
        &OpenSslContainerConfig {
            docker: config.docker.clone(),
            image: config.image.clone(),
            trust_store: config.trust_store.clone(),
            intermediate: config.intermediate.clone(),
            leaf: config.leaf.clone(),
            crl: None,
            validation_time: config.validation_time.clone(),
            timeout: config.timeout,
            max_output_bytes: config.max_output_bytes,
        },
        "oqs-provider",
        VersionTrack::CurrentAndStudy,
    )?)
}
