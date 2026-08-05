use std::{
    fs::File,
    io,
    io::Read,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoundedInputError {
    #[error("{0} is not a regular file")]
    NotAFile(PathBuf),
    #[error("{path} exceeds the {limit}-byte input limit")]
    TooLarge { path: PathBuf, limit: usize },
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, BoundedInputError> {
    let file = File::open(path).map_err(|source| BoundedInputError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| BoundedInputError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BoundedInputError::NotAFile(path.to_owned()));
    }
    if metadata.len() > limit as u64 {
        return Err(BoundedInputError::TooLarge {
            path: path.to_owned(),
            limit,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| BoundedInputError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > limit {
        return Err(BoundedInputError::TooLarge {
            path: path.to_owned(),
            limit,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_file_that_exceeds_the_limit() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"1234").unwrap();

        assert!(matches!(
            read_bounded_file(file.path(), 3),
            Err(BoundedInputError::TooLarge { limit: 3, .. })
        ));
    }
}
