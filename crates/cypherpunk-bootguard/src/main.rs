//! Installed at a stable system path. Missing/broken application runtime is not a
//! dependency. Network-manager Requires/After relationships enforce boot ordering.

use cypherpunk_bootguard::{POLICY, required};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn preferences() -> Result<Option<Vec<u8>>, ()> {
    for parent in ["/etc", "/etc/advanced-vpn", "/etc/advanced-vpn/enrolled"] {
        let meta = match fs::symlink_metadata(parent) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(());
        }
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/etc/advanced-vpn/enrolled/preferences.json")
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 65_536
    {
        return Err(());
    }
    let mut result = Vec::new();
    file.take(65_537).read_to_end(&mut result).map_err(|_| ())?;
    if result.len() > 65_536 {
        return Err(());
    }
    Ok(Some(result))
}

fn nft() -> Result<PathBuf, &'static str> {
    for candidate in ["/usr/sbin/nft", "/sbin/nft"] {
        let Ok(path) = fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.mode() & 0o111 != 0
            && path
                .ancestors()
                .skip(1)
                .all(|p| fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
        {
            return Ok(path);
        }
    }
    Err("trusted nftables program is unavailable")
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--print-policy"] {
        print!("{POLICY}");
        return Ok(());
    }
    if !args.is_empty() {
        return Err("guard accepts no state, policy or command overrides");
    }
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("early guard requires root");
    }
    let marker = match fs::symlink_metadata("/etc/advanced-vpn/whole-device.guard") {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    };
    let config = preferences();
    let config = config
        .as_ref()
        .map(|value| value.as_deref())
        .map_err(|_| ());
    if !required(marker, config) {
        return Ok(());
    }
    let mut child = Command::new(nft()?)
        .args(["-f", "-"])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "cannot start early guard")?;
    if child
        .stdin
        .take()
        .ok_or("guard pipe unavailable")?
        .write_all(POLICY.as_bytes())
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err("cannot write early guard policy");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err("kernel rejected early guard policy"),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("early guard did not finish");
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
