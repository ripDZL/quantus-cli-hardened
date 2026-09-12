use crate::{
    chain::client::QuantusClient,
    error::{QuantusError, Result},
    log_print,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

impl DoctorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    fn push(&mut self, name: impl Into<String>, status: DoctorStatus, detail: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }

    pub fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Fail)
            .count()
    }

    pub fn warnings(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == DoctorStatus::Warn)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointSecurity {
    SecureTls,
    LocalPlaintext,
    RemotePlaintext,
    Invalid,
}

fn ws_url_targets_loopback(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("ws://") else {
        return false;
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);

    if let Some(bracketed) = host_port.strip_prefix('[') {
        let Some(end) = bracketed.find(']') else {
            return false;
        };
        return bracketed[..end]
            .parse::<std::net::Ipv6Addr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    }

    let host = host_port.split(':').next().unwrap_or_default();

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    host.parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn classify_endpoint(url: &str) -> EndpointSecurity {
    if let Some(rest) = url.strip_prefix("wss://") {
        if rest.split(['/', '?', '#']).next().unwrap_or_default().is_empty() {
            EndpointSecurity::Invalid
        } else {
            EndpointSecurity::SecureTls
        }
    } else if url.starts_with("ws://") {
        if ws_url_targets_loopback(url) {
            EndpointSecurity::LocalPlaintext
        } else {
            EndpointSecurity::RemotePlaintext
        }
    } else {
        EndpointSecurity::Invalid
    }
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn wallet_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".quantus").join("wallets"))
}

#[cfg(windows)]
fn validate_wallet_path(path: &Path, directory: bool) -> std::result::Result<(), String> {
    crate::wallet::windows_security::validate_wallet_path(path, directory)
        .map_err(|e| e.to_string())
}

#[cfg(unix)]
fn validate_wallet_path(path: &Path, directory: bool) -> std::result::Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("path is a symbolic link".to_string());
    }
    if directory && !metadata.is_dir() {
        return Err("expected a directory".to_string());
    }
    if !directory && !metadata.is_file() {
        return Err("expected a regular file".to_string());
    }

    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if metadata.uid() != current_uid {
        return Err(format!(
            "owner uid {} does not match current uid {}",
            metadata.uid(),
            current_uid
        ));
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!("permissions {mode:o} allow group/other access"));
    }

    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn validate_wallet_path(_path: &Path, _directory: bool) -> std::result::Result<(), String> {
    Err("wallet ACL verification is not implemented on this platform".to_string())
}

fn inspect_wallet_store(report: &mut DoctorReport) {
    let Some(dir) = wallet_dir() else {
        report.push(
            "Wallet storage",
            DoctorStatus::Fail,
            "Could not determine the current user's home directory.",
        );
        return;
    };

    if !dir.exists() {
        report.push(
            "Wallet storage",
            DoctorStatus::Info,
            "Wallet directory has not been created yet.",
        );
        return;
    }

    match validate_wallet_path(&dir, true) {
        Ok(()) => report.push(
            "Wallet directory protection",
            DoctorStatus::Pass,
            "Owner and access controls are restricted to the expected account boundary.",
        ),
        Err(reason) => report.push(
            "Wallet directory protection",
            DoctorStatus::Fail,
            format!(
                "Wallet directory security check failed: {reason}. Run a local wallet command such as `quantus wallet list` once to apply the hardened ACL migration, then run doctor again."
            ),
        ),
    }

    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            report.push(
                "Wallet file protection",
                DoctorStatus::Fail,
                format!("Could not enumerate the wallet directory: {e}"),
            );
            return;
        }
    };

    let mut wallets = 0usize;
    let mut insecure = 0usize;
    let mut malformed = 0usize;

    for entry in entries {
        let Ok(entry) = entry else {
            malformed += 1;
            continue;
        };
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }

        wallets += 1;
        if validate_wallet_path(&path, false).is_err() {
            insecure += 1;
        }
    }

    if malformed > 0 {
        report.push(
            "Wallet file enumeration",
            DoctorStatus::Warn,
            format!("{malformed} wallet-directory entries could not be inspected."),
        );
    }

    if insecure == 0 {
        report.push(
            "Wallet file protection",
            DoctorStatus::Pass,
            format!("{wallets} wallet file(s) checked; no insecure wallet ACLs detected."),
        );
    } else {
        report.push(
            "Wallet file protection",
            DoctorStatus::Fail,
            format!(
                "{insecure} of {wallets} wallet file(s) failed access-control validation. Run `quantus wallet list` once to migrate existing wallet ACLs, then re-run doctor."
            ),
        );
    }
}

fn inspect_secret_environment(report: &mut DoctorReport) {
    let global_set = std::env::var_os("QUANTUS_WALLET_PASSWORD").is_some();
    let scoped_count = std::env::vars_os()
        .filter(|(key, _)| {
            let key = key.to_string_lossy();
            key.starts_with("QUANTUS_WALLET_PASSWORD_")
        })
        .count();

    if global_set || scoped_count > 0 {
        let mut parts = Vec::new();
        if global_set {
            parts.push("global password variable is set".to_string());
        }
        if scoped_count > 0 {
            parts.push(format!("{scoped_count} wallet-specific password variable(s) are set"));
        }
        report.push(
            "Environment secret exposure",
            DoctorStatus::Warn,
            format!(
                "{}. Environment variables can leak through child processes, diagnostics, or crash capture; prefer an owner-only password file or the interactive prompt.",
                parts.join("; ")
            ),
        );
    } else {
        report.push(
            "Environment secret exposure",
            DoctorStatus::Pass,
            "No Quantus wallet password environment variables are set.",
        );
    }
}

fn inspect_endpoint(report: &mut DoctorReport, node_url: &str) -> EndpointSecurity {
    let security = classify_endpoint(node_url);
    let insecure_override = env_flag_enabled("QUANTUS_ALLOW_INSECURE_REMOTE_WS");

    match security {
        EndpointSecurity::SecureTls => report.push(
            "RPC transport",
            DoctorStatus::Pass,
            "Remote-capable TLS WebSocket transport (wss://) is configured.",
        ),
        EndpointSecurity::LocalPlaintext => report.push(
            "RPC transport",
            DoctorStatus::Pass,
            "Plaintext WebSocket is restricted to a loopback endpoint.",
        ),
        EndpointSecurity::RemotePlaintext => {
            let detail = if insecure_override {
                "Remote plaintext WebSocket is configured and the insecure override is enabled. Traffic can be observed or modified in transit."
            } else {
                "Remote plaintext WebSocket is configured. The hardened client should reject this endpoint; use wss://."
            };
            report.push("RPC transport", DoctorStatus::Fail, detail);
        }
        EndpointSecurity::Invalid => report.push(
            "RPC transport",
            DoctorStatus::Fail,
            "Endpoint is not a valid ws:// or wss:// configuration.",
        ),
    }

    if insecure_override {
        report.push(
            "Insecure RPC override",
            DoctorStatus::Warn,
            "QUANTUS_ALLOW_INSECURE_REMOTE_WS is enabled.",
        );
    } else {
        report.push(
            "Insecure RPC override",
            DoctorStatus::Pass,
            "Remote plaintext RPC override is not enabled.",
        );
    }

    security
}

async fn inspect_runtime(
    report: &mut DoctorReport,
    node_url: &str,
    endpoint: EndpointSecurity,
    offline: bool,
) {
    if offline {
        report.push(
            "Node/runtime compatibility",
            DoctorStatus::Info,
            "Skipped because --offline was requested.",
        );
        return;
    }

    if matches!(endpoint, EndpointSecurity::RemotePlaintext | EndpointSecurity::Invalid) {
        report.push(
            "Node/runtime compatibility",
            DoctorStatus::Info,
            "Skipped because the configured endpoint failed transport-security validation.",
        );
        return;
    }

    match QuantusClient::new(node_url).await {
        Ok(_) => report.push(
            "Node/runtime compatibility",
            DoctorStatus::Pass,
            "Connected successfully and the runtime identity/version checks passed.",
        ),
        Err(e) => report.push(
            "Node/runtime compatibility",
            DoctorStatus::Fail,
            format!("Connection or runtime validation failed: {e}"),
        ),
    }
}

pub async fn collect_doctor_report(node_url: &str, offline: bool) -> DoctorReport {
    let mut report = DoctorReport::default();

    report.push(
        "CLI version",
        DoctorStatus::Info,
        format!("quantus-cli {}", env!("CARGO_PKG_VERSION")),
    );

    match std::env::current_exe() {
        Ok(path) => report.push(
            "Executable",
            DoctorStatus::Info,
            format!("Running from {}", path.display()),
        ),
        Err(e) => report.push(
            "Executable",
            DoctorStatus::Warn,
            format!("Could not resolve the running executable path: {e}"),
        ),
    }

    inspect_wallet_store(&mut report);
    inspect_secret_environment(&mut report);
    let endpoint = inspect_endpoint(&mut report, node_url);
    inspect_runtime(&mut report, node_url, endpoint, offline).await;

    match crate::cli::update::release_trust_summary() {
        Ok(detail) => report.push("Updater authenticity", DoctorStatus::Pass, detail),
        Err(e) => report.push(
            "Updater authenticity",
            DoctorStatus::Warn,
            format!("Signed updater trust is not fully configured: {e}"),
        ),
    }

    report.push(
        "Dependency audit",
        DoctorStatus::Info,
        "Runtime doctor does not execute Cargo tooling; release/source validation should continue to run cargo audit and cargo-deny.",
    );

    report
}

pub async fn handle_doctor_command(node_url: &str, offline: bool) -> Result<()> {
    let report = collect_doctor_report(node_url, offline).await;

    log_print!("🔎 Quantus security doctor");
    for check in &report.checks {
        log_print!("[{}] {} — {}", check.status.label(), check.name, check.detail);
    }

    let failures = report.failures();
    let warnings = report.warnings();
    log_print!(
        "Doctor summary: {} failure(s), {} warning(s), {} total check(s)",
        failures,
        warnings,
        report.checks.len()
    );

    if failures > 0 {
        return Err(QuantusError::Generic(format!(
            "security doctor found {failures} failing check(s)"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_loopback_detection_is_strict() {
        assert_eq!(
            classify_endpoint("ws://127.0.0.1:9944"),
            EndpointSecurity::LocalPlaintext
        );
        assert_eq!(
            classify_endpoint("ws://127.42.0.7:9944/path"),
            EndpointSecurity::LocalPlaintext
        );
        assert_eq!(
            classify_endpoint("ws://[::1]:9944"),
            EndpointSecurity::LocalPlaintext
        );
        assert_eq!(
            classify_endpoint("ws://localhost:9944"),
            EndpointSecurity::LocalPlaintext
        );
        assert_eq!(
            classify_endpoint("ws://127.attacker.example:9944"),
            EndpointSecurity::RemotePlaintext
        );
        assert_eq!(
            classify_endpoint("ws://127.example.com:9944"),
            EndpointSecurity::RemotePlaintext
        );
        assert_eq!(
            classify_endpoint("wss://node.example.com"),
            EndpointSecurity::SecureTls
        );
        assert_eq!(classify_endpoint("https://example.com"), EndpointSecurity::Invalid);
    }

    #[test]
    fn report_counts_only_warn_and_fail_severities() {
        let mut report = DoctorReport::default();
        report.push("pass", DoctorStatus::Pass, "ok");
        report.push("warn", DoctorStatus::Warn, "warning");
        report.push("fail", DoctorStatus::Fail, "bad");
        report.push("info", DoctorStatus::Info, "note");
        assert_eq!(report.failures(), 1);
        assert_eq!(report.warnings(), 1);
    }
}
