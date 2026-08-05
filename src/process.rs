use std::{
    ffi::OsString,
    io::{self, Read},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

use crate::{EncodedStream, ProcessRecord};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessOutput {
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub elapsed: Duration,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
}

pub fn run_program(
    program: &Path,
    args: &[OsString],
    limits: ProcessLimits,
) -> io::Result<ProcessOutput> {
    if limits.max_output_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "max_output_bytes must be greater than zero",
        ));
    }

    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout is available");
    let stderr = child.stderr.take().expect("piped stderr is available");
    let output_limit = limits.max_output_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));

    let (status, timed_out) = match child.wait_timeout(limits.timeout)? {
        Some(status) => (status, false),
        None => {
            terminate(&mut child)?;
            (child.wait()?, true)
        }
    };

    Ok(ProcessOutput {
        status_code: status.code(),
        timed_out,
        elapsed: started.elapsed(),
        stdout: join_reader(stdout_reader)?,
        stderr: join_reader(stderr_reader)?,
    })
}

#[cfg(unix)]
fn terminate(child: &mut std::process::Child) -> io::Result<()> {
    let process_group = i32::try_from(child.id())
        .map_err(|_| io::Error::other("child process identifier is out of range"))?;
    // SAFETY: The child starts a new process group with its process identifier. A negative
    // identifier addresses that exact group. SIGKILL does not use a pointer.
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut std::process::Child) -> io::Result<()> {
    child.kill()
}

impl From<&ProcessOutput> for ProcessRecord {
    fn from(output: &ProcessOutput) -> Self {
        Self {
            status_code: output.status_code,
            timed_out: output.timed_out,
            elapsed_milliseconds: output.elapsed.as_millis().try_into().unwrap_or(u64::MAX),
            stdout: encode_stream(&output.stdout),
            stderr: encode_stream(&output.stderr),
        }
    }
}

fn encode_stream(stream: &CapturedStream) -> EncodedStream {
    EncodedStream {
        encoding: "base64".to_owned(),
        data: STANDARD.encode(&stream.bytes),
        sha256: sha256_hex(&stream.bytes),
        captured_bytes: stream.bytes.len(),
        truncated: stream.truncated,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hex, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hex
}

fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<CapturedStream> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..read.min(remaining)]);
        truncated |= read > remaining;
    }
    Ok(CapturedStream { bytes, truncated })
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<CapturedStream>>,
) -> io::Result<CapturedStream> {
    handle
        .join()
        .map_err(|_| io::Error::other("output reader thread failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_bounded_without_blocking_the_child() {
        let output = run_program(
            Path::new("/usr/bin/yes"),
            &[],
            ProcessLimits {
                timeout: Duration::from_millis(20),
                max_output_bytes: 64,
            },
        )
        .unwrap();

        assert!(output.timed_out);
        assert_eq!(output.stdout.bytes.len(), 64);
        assert!(output.stdout.truncated);
    }

    #[test]
    fn completed_process_returns_its_status_and_output() {
        let output = run_program(
            Path::new("/usr/bin/printf"),
            &[OsString::from("verified")],
            ProcessLimits {
                timeout: Duration::from_secs(1),
                max_output_bytes: 64,
            },
        )
        .unwrap();

        assert!(!output.timed_out);
        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout.bytes, b"verified");
        assert!(!output.stdout.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_descendant_processes() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("descendant-ran");
        let command = format!("(sleep 1; /usr/bin/touch '{}') & sleep 5", marker.display());
        let output = run_program(
            Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from(command)],
            ProcessLimits {
                timeout: Duration::from_millis(50),
                max_output_bytes: 64,
            },
        )
        .unwrap();

        assert!(output.timed_out);
        thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists());
    }
}
