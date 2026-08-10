use std::{collections::HashSet, ffi::OsString, fs, io, io::Write, path::Path};

pub(crate) fn readable_tempfile(contents: &[u8]) -> io::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(contents)?;
    file.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    Ok(file)
}

pub(crate) fn isolated_arguments(
    image: &str,
    mounts: &[(&Path, &str)],
    command: &[OsString],
) -> Result<Vec<OsString>, io::Error> {
    if image.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "container image must not be empty",
        ));
    }
    let mut arguments = vec![
        "run".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--network=none".into(),
        "--ipc=none".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        "--user=65532:65532".into(),
        "--pids-limit=64".into(),
        "--memory=768m".into(),
        "--cpus=2".into(),
        "--ulimit=nofile=64:64".into(),
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m".into(),
    ];
    let mut destinations = HashSet::new();
    for (source, destination) in mounts {
        if !destination.starts_with("/input/")
            || !destination
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
            || !destinations.insert(*destination)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "container mount destination is not a unique /input path",
            ));
        }
        let source = fs::canonicalize(source)?;
        let source = source.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "container mount path is not UTF-8",
            )
        })?;
        if source.contains([',', '\n', '\r']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "container mount path contains an unsafe delimiter",
            ));
        }
        arguments.extend([
            "--mount".into(),
            format!("type=bind,src={source},dst={destination},readonly").into(),
        ]);
    }
    arguments.push("--".into());
    arguments.push(image.into());
    arguments.extend_from_slice(command);
    Ok(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn temporary_container_inputs_are_readable_by_the_container_user() {
        use std::os::unix::fs::PermissionsExt;

        let input = readable_tempfile(b"input").unwrap();

        assert_eq!(
            input.as_file().metadata().unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn container_arguments_enforce_runtime_confinement() {
        let input = tempfile::NamedTempFile::new().unwrap();
        let arguments = isolated_arguments(
            "--hostile-image-name",
            &[(input.path(), "/input/leaf.pem")],
            &["--version".into()],
        )
        .unwrap();
        let values = arguments
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();

        for required in [
            "--pull=never",
            "--network=none",
            "--ipc=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65532:65532",
            "--pids-limit=64",
            "--memory=768m",
            "--cpus=2",
            "--ulimit=nofile=64:64",
        ] {
            assert!(values.iter().any(|value| value == required));
        }
        let separator = values.iter().position(|value| value == "--").unwrap();
        assert_eq!(values[separator + 1], "--hostile-image-name");
    }

    #[test]
    fn mount_delimiters_and_duplicate_destinations_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let unsafe_path = directory.path().join("leaf,extra.pem");
        fs::write(&unsafe_path, b"input").unwrap();
        assert!(
            isolated_arguments("image", &[(unsafe_path.as_path(), "/input/leaf.pem")], &[],)
                .is_err()
        );

        let input = tempfile::NamedTempFile::new().unwrap();
        assert!(
            isolated_arguments(
                "image",
                &[
                    (input.path(), "/input/leaf.pem"),
                    (input.path(), "/input/leaf.pem"),
                ],
                &[],
            )
            .is_err()
        );
    }
}
