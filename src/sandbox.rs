//! Post-startup confinement for the data-plane daemons (adapted from the confinement
//! Tails applies with AppArmor and GrapheneOS with seccomp-bpf, using maintained crates,
//! nothing hand-rolled).
//!
//! Once a daemon has read its configuration and keys, opened its sockets and its TUN
//! device, it never again needs to start a program, debug another process, change
//! namespaces, load kernel code or touch files outside a few directories. `confine`
//! removes those abilities for the rest of the process's life:
//!
//! - **seccomp** (`seccompiler`, the Firecracker project's filter compiler): the calls in
//!   [`DENIED`] fail with `EPERM`. Everything else stays allowed, so a rarely used path
//!   cannot kill the data plane.
//! - **Landlock** (`landlock`): the filesystem becomes read-only below the given read
//!   paths, writable only below the given write paths, and closed everywhere else.
//!   Best effort: a kernel without Landlock leaves the filesystem open, and the
//!   returned [`Confinement`] says so.
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// System calls a confined daemon may never make again: starting programs, reading or
/// writing other processes, namespaces and mounts, kernel code and keys, and a few
/// calls exploits favour.
pub const DENIED: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_process_madvise,
    libc::SYS_pidfd_getfd,
    libc::SYS_kcmp,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsmount,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_personality,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
];

/// What a confined process may still reach on the filesystem.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Directories readable (not writable) after confinement.
    pub read: Vec<PathBuf>,
    /// Directories readable and writable after confinement.
    pub write: Vec<PathBuf>,
}

impl Policy {
    /// The usual policy: system files readable (name lookup reads `/etc` and loads
    /// libraries from `/usr`), and only the given directories writable.
    pub fn writing(dirs: impl IntoIterator<Item = PathBuf>) -> Self {
        let read = [
            "/etc",
            "/usr",
            "/lib",
            "/lib64",
            "/proc/self",
            "/dev/urandom",
            "/dev/null",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        Self {
            read,
            write: dirs.into_iter().collect(),
        }
    }

    /// A daemon's policy: system files and the directories holding `files` readable
    /// (its configuration and certificates, which handshakes re-read), `write_dirs`
    /// writable (its statistics), and the TUN device when `tun`.
    pub fn daemon<'a>(
        files: impl IntoIterator<Item = &'a Path>,
        write_dirs: impl IntoIterator<Item = PathBuf>,
        tun: bool,
    ) -> Self {
        let mut p = Self::writing(write_dirs);
        p.read.extend(files.into_iter().map(Self::parent_of));
        if tun {
            p.write.push(PathBuf::from("/dev/net/tun"));
        }
        p
    }

    /// The directory holding `file` (for a daemon that writes one status file).
    pub fn parent_of(file: &Path) -> PathBuf {
        file.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf()
    }
}

/// What `confine` achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confinement {
    /// The seccomp filter is installed (always true when `confine` returns Ok).
    pub seccomp: bool,
    /// Landlock fully enforces the policy (false on kernels without Landlock).
    pub landlock: bool,
}

fn seccomp() -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;

    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| anyhow::anyhow!("seccomp: unsupported architecture: {e:?}"))?;
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        DENIED.iter().map(|&s| (s, vec![])).collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .context("seccomp filter")?;
    let program: BpfProgram = filter.try_into().context("seccomp program")?;
    seccompiler::apply_filter(&program).context("installing the seccomp filter")?;
    Ok(())
}

fn landlock(p: &Policy) -> Result<bool> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };

    let abi = ABI::V3;
    let existing = |paths: &[PathBuf]| {
        paths
            .iter()
            .filter(|x| x.exists())
            .cloned()
            .collect::<Vec<_>>()
    };
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(
            existing(&p.read),
            AccessFs::from_read(abi),
        ))?
        .add_rules(path_beneath_rules(
            existing(&p.write),
            AccessFs::from_all(abi),
        ))?
        .restrict_self()
        .context("restricting the filesystem")?;
    Ok(status.ruleset == RulesetStatus::FullyEnforced)
}

/// Confine this process for the rest of its life (all its threads, and anything it
/// would ever start). Call it once, after every file, socket and device the daemon needs
/// is open. The filesystem rules go first: installing them needs calls the seccomp
/// filter then forbids nothing of, but the order keeps the two independent.
pub fn confine(p: &Policy) -> Result<Confinement> {
    let landlock = landlock(p)?;
    seccomp()?;
    Ok(Confinement {
        seccomp: true,
        landlock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `probe` in a fresh copy of this test binary, so confinement never touches
    /// the test runner itself. The child prints one line per check.
    fn in_child(probe: &str) -> String {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sandbox::tests::child",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("AVPN_SANDBOX_PROBE", probe)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn child() {
        let Ok(probe) = std::env::var("AVPN_SANDBOX_PROBE") else {
            return;
        };
        let dir =
            PathBuf::from(std::env::var("AVPN_SANDBOX_DIR").unwrap_or_else(|_| "/tmp".into()));
        let writable = std::env::temp_dir().join(format!("avpn-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&writable).unwrap();
        let c = confine(&Policy::writing([writable.clone()])).unwrap();
        println!("landlock={}", c.landlock);
        let report = |name: &str, r: std::io::Result<()>| match r {
            Ok(()) => println!("{name}=allowed"),
            Err(e) => println!("{name}=denied:{}", e.raw_os_error().unwrap_or(0)),
        };
        match probe.as_str() {
            "exec" => report(
                "exec",
                std::process::Command::new("/bin/true").status().map(|_| ()),
            ),
            "ptrace" => {
                // SAFETY: PTRACE_TRACEME takes no pointers; the call only reports permission.
                let r = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
                report(
                    "ptrace",
                    if r == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    },
                )
            }
            "unshare" => {
                // SAFETY: unshare takes a flag word only.
                let r = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
                report(
                    "unshare",
                    if r == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    },
                )
            }
            "files" => {
                report("write-allowed", std::fs::write(writable.join("ok"), b"x"));
                report(
                    "read-etc",
                    std::fs::read("/etc/hostname").map(|_| ()).or_else(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    }),
                );
                report(
                    "write-outside",
                    std::fs::write(
                        dir.join(format!("avpn-escape-{}", std::process::id())),
                        b"x",
                    ),
                );
                report(
                    "read-home",
                    std::fs::read_dir(std::env::var("HOME").unwrap_or("/root".into())).map(|_| ()),
                );
            }
            "work" => {
                // Ordinary daemon work keeps working: threads, sockets, time, randomness.
                let t = std::thread::spawn(|| 1 + 1)
                    .join()
                    .map(|_| ())
                    .map_err(|_| std::io::Error::other("thread"));
                report("thread", t);
                report("udp", std::net::UdpSocket::bind("127.0.0.1:0").map(|_| ()));
                let mut b = [0u8; 16];
                // SAFETY: `b` is a live 16-byte buffer and 16 is its length.
                let r = unsafe { libc::getrandom(b.as_mut_ptr().cast(), 16, 0) };
                report(
                    "getrandom",
                    if r == 16 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    },
                );
            }
            _ => unreachable!(),
        }
        let _ = std::fs::remove_dir_all(&writable);
    }

    #[test]
    fn a_confined_daemon_cannot_start_programs_trace_or_change_namespaces() {
        assert!(
            in_child("exec").contains("exec=denied:1"),
            "{}",
            in_child("exec")
        );
        assert!(in_child("ptrace").contains("ptrace=denied:1"));
        assert!(in_child("unshare").contains("unshare=denied:1"));
    }

    #[test]
    fn a_confined_daemon_keeps_doing_its_normal_work() {
        let out = in_child("work");
        for check in ["thread=allowed", "udp=allowed", "getrandom=allowed"] {
            assert!(out.contains(check), "{check} missing in:\n{out}");
        }
    }

    #[test]
    fn a_confined_daemon_writes_only_its_own_directory() {
        let out = in_child("files");
        assert!(out.contains("write-allowed=allowed"), "{out}");
        assert!(out.contains("read-etc=allowed"), "{out}");
        // Where the kernel has Landlock, confinement must have used it: a silent fallback
        // to an open filesystem is a failure, not a skip.
        let kernel_has_landlock = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|l| l.split(',').any(|m| m.trim() == "landlock"))
            .unwrap_or(false);
        if kernel_has_landlock {
            assert!(
                out.contains("landlock=true"),
                "Landlock not enforced:\n{out}"
            );
        }
        if out.contains("landlock=true") {
            assert!(out.contains("write-outside=denied"), "{out}");
            assert!(out.contains("read-home=denied"), "{out}");
        } else {
            eprintln!("Landlock unavailable on this kernel: filesystem rules not enforced");
        }
    }
}
