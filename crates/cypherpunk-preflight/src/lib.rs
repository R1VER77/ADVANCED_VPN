//! Shared-policy readiness decisions. Synthetic facts exist as a test API, never
//! as a production CLI path/root override. Readiness does not activate a VPN.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const POLICY: &str = include_str!("../../../tools/preflight-policy.json");

#[derive(Deserialize)]
pub struct Policy {
    pub schema: u32,
    pub tested: Vec<[String; 2]>,
    pub families: Vec<String>,
    pub architectures: Vec<String>,
    pub release_glibc: [u32; 2],
    pub systemd_creds: u32,
    pub need_mb: u64,
    pub programs: Vec<String>,
    pub system_paths: Vec<String>,
}

impl Policy {
    pub fn load() -> Result<Self, String> {
        let policy: Self = serde_json::from_str(POLICY).map_err(|e| e.to_string())?;
        if policy.schema != 1 {
            return Err("unknown preflight policy schema".into());
        }
        Ok(policy)
    }
}

#[derive(Default, Deserialize)]
pub struct Facts {
    pub os_id: String,
    pub os_version: String,
    pub os_like: Vec<String>,
    pub machine: String,
    pub glibc: Option<[u32; 2]>,
    pub glibc_need: [u32; 2],
    pub tun: bool,
    pub programs: BTreeSet<String>,
    pub nf_tables: bool,
    pub seccomp: bool,
    pub landlock: bool,
    pub systemd: Option<u32>,
    pub free_mb: u64,
    pub package_mb: u64,
    pub vpn_interfaces: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Options {
    pub operator_only: bool,
    pub systemd_creds: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub detail: serde_json::Value,
    pub fix: Option<String>,
    pub package: Option<String>,
}

impl Finding {
    fn new(code: &str, severity: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            severity: severity.into(),
            message: message.into(),
            detail: serde_json::json!({}),
            fix: None,
            package: None,
        }
    }
}

#[derive(Serialize)]
pub struct Report {
    pub schema: u32,
    pub ready: bool,
    pub blockers: usize,
    pub warnings: usize,
    pub findings: Vec<Finding>,
    pub scope: &'static str,
}

pub fn evaluate(f: &Facts, o: &Options, p: &Policy) -> Report {
    let mut out = Vec::new();
    let mut add = |code, severity, message| out.push(Finding::new(code, severity, message));
    if p.tested
        .iter()
        .any(|x| x == &[f.os_id.clone(), f.os_version.clone()])
    {
        add(
            "os_tested",
            "ok",
            "This distribution/version is a documented release target.",
        );
    } else if std::iter::once(&f.os_id)
        .chain(f.os_like.iter())
        .any(|x| p.families.contains(x))
    {
        add(
            "os_untested",
            "warning",
            "This distribution family is known, but this version is untested.",
        );
    } else {
        add(
            "os_unknown",
            "blocker",
            "This distribution is not supported.",
        );
    }
    if p.architectures.contains(&f.machine) {
        add("arch", "ok", "The release supports this architecture.");
    } else {
        add(
            "arch_unsupported",
            "blocker",
            "The release does not support this architecture.",
        );
    }
    match f.glibc {
        Some(have) if have >= f.glibc_need => add(
            "glibc",
            "ok",
            "The host GNU C library meets the package ABI requirement.",
        ),
        Some(_) => add(
            "glibc_old",
            "blocker",
            "The package needs a newer GNU C library.",
        ),
        None => add(
            "glibc_unknown",
            "blocker",
            "The host GNU C library could not be verified.",
        ),
    }
    if !o.operator_only {
        if f.tun {
            add("tun", "ok", "/dev/net/tun is present.");
        } else {
            add("tun_missing", "blocker", "/dev/net/tun is unavailable.");
        }
        let missing: Vec<_> = p
            .programs
            .iter()
            .filter(|x| !f.programs.contains(*x))
            .collect();
        if missing.is_empty() {
            add(
                "programs",
                "ok",
                "ip, nft, mount and systemctl are installed.",
            );
        }
        if f.nf_tables {
            add("nf_tables", "ok", "The kernel has nf_tables.");
        } else {
            add(
                "nf_tables_missing",
                "blocker",
                "The kill switch requires nf_tables.",
            );
        }
        if f.seccomp {
            add("seccomp", "ok", "The kernel supports seccomp.");
        } else {
            add(
                "seccomp_missing",
                "blocker",
                "The network sandbox requires seccomp.",
            );
        }
        if f.landlock {
            add("landlock", "ok", "Landlock is in the visible LSM list.");
        } else {
            add(
                "landlock_off",
                "warning",
                "Landlock is unconfirmed; runtime checks it again.",
            );
        }
        match f.systemd {
            Some(v) if v >= p.systemd_creds => {
                add("systemd", "ok", "systemd supports credential sealing.")
            }
            Some(_) => add(
                "systemd_old",
                if o.systemd_creds { "warning" } else { "info" },
                "This systemd cannot seal keys; use supported hardware protection.",
            ),
            None => add(
                "systemd_unknown",
                "info",
                "Could not read the systemd version.",
            ),
        }
        for program in missing {
            let mut finding = Finding::new(
                "program_missing",
                "blocker",
                "A required trusted system program is missing.",
            );
            finding.detail = serde_json::json!({"program": program});
            finding.package = Some(program.clone());
            out.push(finding);
        }
    }
    // This binary intentionally runs before Python. The bootstrap must verify
    // and select the bundled runtime; it never assumes host Python readiness.
    let enough = f.free_mb >= p.need_mb.saturating_add(f.package_mb);
    out.push(Finding::new(
        if enough { "space" } else { "space_low" },
        if enough { "ok" } else { "blocker" },
        if enough {
            "Storage meets the installation requirement."
        } else {
            "Storage is insufficient for installation and replacement."
        },
    ));
    if !o.operator_only && !f.vpn_interfaces.is_empty() {
        let mut finding = Finding::new(
            "other_vpns",
            "info",
            "VPN-like interfaces are present; review routing before activation.",
        );
        finding.detail = serde_json::json!({"interfaces": f.vpn_interfaces});
        out.push(finding);
    }
    for error in &f.errors {
        let mut finding = Finding::new(
            "check_failed",
            "blocker",
            "A required host check failed; readiness is unverified.",
        );
        finding.detail = serde_json::json!({"check": error});
        out.push(finding);
    }
    out.sort_by_key(|x| match x.severity.as_str() {
        "blocker" => 0,
        "warning" => 1,
        "info" => 2,
        _ => 3,
    });
    let blockers = out.iter().filter(|x| x.severity == "blocker").count();
    let warnings = out.iter().filter(|x| x.severity == "warning").count();
    Report {
        schema: 1,
        ready: blockers == 0,
        blockers,
        warnings,
        findings: out,
        scope: "host checks before bundled runtime; optional hardware/provider checks require the installed setup tool",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_findings_match_the_same_fixtures_as_python() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tools/preflight-fixtures.json")).unwrap();
        assert_eq!(fixture["schema"], 1);
        let policy = Policy::load().unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let mut facts = fixture["base"].clone();
            for (key, value) in case["set"].as_object().unwrap() {
                facts[key] = value.clone();
            }
            let facts: Facts = serde_json::from_value(facts).unwrap();
            let options: Options = serde_json::from_value(
                case.get("options")
                    .cloned()
                    .unwrap_or(serde_json::json!({})),
            )
            .unwrap();
            let report = evaluate(&facts, &options, &policy);
            let mut actual: Vec<[String; 2]> = report
                .findings
                .into_iter()
                .map(|x| [x.code, x.severity])
                .collect();
            let mut expected: Vec<[String; 2]> = fixture["baseline"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| !case["remove"].as_array().unwrap().contains(&row[0]))
                .map(|row| serde_json::from_value(row.clone()).unwrap())
                .collect();
            expected.extend(
                case["add"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|row| serde_json::from_value::<[String; 2]>(row.clone()).unwrap()),
            );
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected, "{}", case["name"]);
        }
    }
}
