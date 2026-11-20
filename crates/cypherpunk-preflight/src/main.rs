//! Linux-only read-only host collection. No fixture, root override or apply mode.

#[cfg(not(target_os = "linux"))]
compile_error!("cypherpunk-preflight is a Linux bootstrap; other platforms need native adapters");

use cypherpunk_preflight::{Facts, Options, Policy, evaluate};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File},
    io::{Read, Result},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn text(path: impl AsRef<Path>, limit: u64) -> Result<String> {
    let mut value = String::new();
    File::open(path)?
        .take(limit + 1)
        .read_to_string(&mut value)?;
    if value.len() as u64 > limit {
        return Err(std::io::Error::other("host text exceeds bound"));
    }
    Ok(value)
}

fn trusted_program(name: &str, policy: &Policy) -> Option<PathBuf> {
    for directory in &policy.system_paths {
        let Ok(path) = fs::canonicalize(Path::new(directory).join(name)) else {
            continue;
        };
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || meta.mode() & 0o111 == 0
        {
            continue;
        }
        if path
            .ancestors()
            .skip(1)
            .all(|p| fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
        {
            return Some(path);
        }
    }
    None
}

fn command_text(path: &Path, args: &[&str]) -> Option<String> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    if !success {
        return None;
    }
    let mut output = String::new();
    child
        .stdout
        .take()?
        .take(65_537)
        .read_to_string(&mut output)
        .ok()?;
    (output.len() <= 65_536).then_some(output)
}

fn version(value: &str) -> Option<[u32; 2]> {
    for part in value.split_whitespace() {
        let mut numbers = part.split('.');
        if let (Some(a), Some(b)) = (numbers.next(), numbers.next())
            && let (Ok(a), Ok(b)) = (a.parse(), b.parse())
        {
            return Some([a, b]);
        }
    }
    None
}

fn files(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            files(&entry.path(), output)?;
        } else if kind.is_file() {
            output.push(entry.path());
        }
        // No traversal through a release-controlled symlink.
    }
    Ok(())
}

fn package(path: &Path, default: [u32; 2]) -> Result<([u32; 2], u64)> {
    let mut paths = Vec::new();
    files(path, &mut paths)?;
    let mut size = 0_u64;
    let mut required = [0, 0];
    let mut elf_files = 0;
    for path in paths {
        size = size
            .checked_add(fs::metadata(&path)?.len())
            .ok_or_else(|| std::io::Error::other("package size overflow"))?;
        let mut file = File::open(path)?;
        let mut magic = [0; 4];
        if file.read_exact(&mut magic).is_err() || magic != *b"\x7fELF" {
            continue;
        }
        elf_files += 1;
        let mut tail = Vec::new();
        let mut buffer = [0; 65_536];
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            tail.extend_from_slice(&buffer[..length]);
            for index in 0..tail.len().saturating_sub(6) {
                if tail.get(index..index + 6) != Some(b"GLIBC_") {
                    continue;
                }
                let remaining = &tail[index + 6..];
                if let Some(end) = remaining.iter().position(|x| *x == 0)
                    && let Ok(value) = std::str::from_utf8(&remaining[..end])
                {
                    let parts: Vec<_> = value.split('.').collect();
                    if parts.len() == 2
                        && let (Ok(a), Ok(b)) = (parts[0].parse(), parts[1].parse())
                    {
                        required = required.max([a, b]);
                    }
                }
            }
            tail = tail[tail.len().saturating_sub(64)..].to_vec();
        }
    }
    if elf_files == 0 {
        return Err(std::io::Error::other("package contains no ELF files"));
    }
    Ok((
        if required == [0, 0] {
            default
        } else {
            required
        },
        size.div_ceil(1 << 20),
    ))
}

fn free_mb(target: &Path) -> Result<u64> {
    let mut path = target;
    while !path.exists() {
        path = path
            .parent()
            .ok_or_else(|| std::io::Error::other("target has no existing ancestor"))?;
    }
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is a NUL-terminated owned CString and value is writable storage
    // for the exact libc output type; it is read only on a successful return.
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statvfs returned success and initialized the complete output struct.
    let value = unsafe { value.assume_init() };
    Ok(value.f_bavail.saturating_mul(value.f_frsize) / (1 << 20))
}

fn vpn_interface(name: &str) -> bool {
    let numeric = |prefix: &str, empty: bool| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            (empty || !rest.is_empty()) && rest.bytes().all(|x| x.is_ascii_digit())
        })
    };
    numeric("wg", true)
        || numeric("tun", false)
        || numeric("tap", false)
        || numeric("avwg", true)
        || numeric("avpn", true)
        || name == "nordlynx"
        || ["proton", "mullvad", "ivpn"].iter().any(|x| {
            name.strip_prefix(x)
                .is_some_and(|rest| rest.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
        })
}

fn collect(policy: &Policy, package_path: Option<&Path>, target: &Path) -> Facts {
    let mut facts = Facts {
        machine: std::env::consts::ARCH.into(),
        glibc_need: policy.release_glibc,
        ..Facts::default()
    };
    let os = text("/etc/os-release", 65_536)
        .or_else(|_| text("/usr/lib/os-release", 65_536))
        .unwrap_or_default();
    let fields: BTreeMap<_, _> = os
        .lines()
        .filter(|x| !x.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim().trim_matches('"')))
        .collect();
    facts.os_id = fields.get("ID").copied().unwrap_or_default().into();
    facts.os_version = fields.get("VERSION_ID").copied().unwrap_or_default().into();
    facts.os_like = fields
        .get("ID_LIKE")
        .copied()
        .unwrap_or_default()
        .split_whitespace()
        .map(String::from)
        .collect();
    facts.glibc = trusted_program("getconf", policy)
        .and_then(|p| command_text(&p, &["GNU_LIBC_VERSION"]))
        .and_then(|s| version(&s));
    facts.tun = Path::new("/dev/net/tun").exists();
    for program in &policy.programs {
        if trusted_program(program, policy).is_some() {
            facts.programs.insert(program.clone());
        }
    }
    let kernel = text("/proc/sys/kernel/osrelease", 4096).unwrap_or_default();
    let modules = Path::new("/lib/modules").join(kernel.trim());
    facts.nf_tables = Path::new("/sys/module/nf_tables").exists()
        || text(modules.join("modules.builtin"), 4 << 20)
            .unwrap_or_default()
            .contains("nf_tables.ko")
        || fs::read_dir(modules.join("kernel/net/netfilter")).is_ok_and(|mut d| {
            d.any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().starts_with("nf_tables.ko")))
        });
    facts.seccomp = text("/proc/self/status", 1 << 20)
        .unwrap_or_default()
        .lines()
        .any(|s| s.starts_with("Seccomp:"));
    facts.landlock = text("/sys/kernel/security/lsm", 65_536)
        .unwrap_or_default()
        .trim()
        .split(',')
        .any(|s| s == "landlock");
    facts.systemd = trusted_program("systemctl", policy)
        .and_then(|p| command_text(&p, &["--version"]))
        .and_then(|s| {
            s.strip_prefix("systemd ")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
        });
    match free_mb(target) {
        Ok(n) => facts.free_mb = n,
        Err(_) => facts.errors.push("check_space".into()),
    }
    if let Some(path) = package_path {
        match package(path, policy.release_glibc) {
            Ok((abi, size)) => {
                facts.glibc_need = abi;
                facts.package_mb = size;
            }
            Err(_) => facts.errors.push("check_package".into()),
        }
    }
    match fs::read_dir("/sys/class/net") {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if vpn_interface(&name) {
                            facts.vpn_interfaces.push(name);
                        }
                    }
                    Err(_) => facts.errors.push("check_other_vpns".into()),
                }
            }
            facts.vpn_interfaces.sort();
        }
        Err(_) => facts.errors.push("check_other_vpns".into()),
    }
    facts
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut package_path = None;
    let mut target = PathBuf::from("/opt");
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => (),
            "--operator-only" => options.operator_only = true,
            "--package" => {
                package_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--package requires a directory");
                    std::process::exit(2)
                })))
            }
            "--target" => {
                target = PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--target requires a directory");
                    std::process::exit(2)
                }))
            }
            "--protect" => match args.next().as_deref() {
                Some("systemd-creds") => options.systemd_creds = true,
                Some("nitrokey" | "operator" | "none") => (),
                _ => {
                    eprintln!("invalid key protection");
                    std::process::exit(2);
                }
            },
            "--help" => {
                println!(
                    "cypherpunk-preflight [--json] [--package DIR] [--target DIR] [--operator-only] [--protect MODE]\nRead-only host checks before the bundled Python runtime; never installs or activates."
                );
                return;
            }
            _ => {
                eprintln!("unknown or unavailable preflight option: {arg}");
                std::process::exit(2);
            }
        }
    }
    if !target.is_absolute() || package_path.as_ref().is_some_and(|p| !p.is_dir()) {
        eprintln!("target must be absolute and package must be a readable directory");
        std::process::exit(2);
    }
    let policy = Policy::load().expect("embedded reviewed policy");
    let report = evaluate(
        &collect(&policy, package_path.as_deref(), &target),
        &options,
        &policy,
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serialization")
    );
    std::process::exit(i32::from(!report.ready));
}
