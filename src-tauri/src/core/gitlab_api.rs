//! Minimal GitLab REST client for the guided backup setup: validate a
//! personal access token against a GitLab instance (gitlab.com or
//! self-hosted), then find the backup project — creating it in the user's
//! personal namespace when the input is a bare name. GitLab has no Device
//! Flow, so a PAT is the only guided auth path; the token itself never
//! appears in URLs, logs, or error messages — callers store it in the OS
//! keychain.
//!
//! Errors carry stable prefixes (`GITLAB_TOKEN_INVALID`, `GITLAB_SCOPE`,
//! `GITLAB_PROJECT_NOT_FOUND`, `GITLAB_URL_INVALID`, `GITLAB_NETWORK`) the
//! frontend maps to plain-language copy.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::skillssh_api::build_http_client;

pub const DEFAULT_BASE_URL: &str = "https://gitlab.com";

#[derive(Debug, Clone, serde::Serialize)]
pub struct GitlabConnectInfo {
    /// Normalized instance base URL (`https://gitlab.example.com`, no trailing
    /// slash) — persisted so the disconnect/revocation UI can build instance
    /// links without re-parsing the remote URL (ambiguous for subpath
    /// deployments).
    pub base_url: String,
    pub username: String,
    /// Full project path (`namespace/project`, may be nested under groups).
    pub project_path: String,
    /// Credential-free HTTPS clone URL.
    pub url: String,
    pub project_created: bool,
    /// False when the connected project's visibility is not `private` —
    /// `internal` projects are readable by every logged-in user of the
    /// instance, which the UI warns about like GitHub's public-repo case.
    /// Projects created by the app are always private; a missing field is
    /// treated as private so a parsing gap can only suppress the warning.
    pub project_private: bool,
}

#[derive(Deserialize)]
struct UserResp {
    username: String,
}

#[derive(Deserialize)]
struct ProjectResp {
    path_with_namespace: String,
    visibility: Option<String>,
}

/// GitLab project path rules (subset): 1–5 slash-separated segments of ASCII
/// letters, digits, `-`, `_`, `.`; no empty/`.`/`..` segments, max 255 chars
/// total; a path ending in `.git`/`.atom` is rejected the way GitLab itself
/// would. A bare single segment targets the token owner's personal namespace;
/// multiple segments address an existing project under groups (deeply nested
/// groups are uncommon but legal, so the segment count is bounded loosely).
pub fn is_valid_project_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 255 {
        return false;
    }
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.last().copied().unwrap_or_default();
    segments.len() <= 20
        && !last.ends_with(".git")
        && !last.ends_with(".atom")
        && segments.iter().all(|seg| {
            !seg.is_empty()
                && *seg != "."
                && *seg != ".."
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
}

/// Normalize a user-entered instance address: trim, default to `https://`
/// when no scheme was given, drop trailing slashes. Self-hosted instances may
/// live behind a plain-HTTP intranet host, a non-standard port, or a subpath
/// (`…/gitlab`) — all allowed. Embedded credentials (`user:token@host`) are
/// rejected rather than stripped: the token belongs in the token field, and
/// silently keeping it would persist it into the saved remote URL.
pub fn normalize_base_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("GITLAB_URL_INVALID: the instance address is empty");
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let (scheme, rest) = with_scheme
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("GITLAB_URL_INVALID: no scheme in the instance address"))?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        bail!("GITLAB_URL_INVALID: only http and https instances are supported");
    }
    let host = rest.split('/').next().unwrap_or_default();
    if host.contains('@') {
        bail!(
            "GITLAB_URL_INVALID: credentials in the instance address are not supported — put the token in the token field"
        );
    }
    let host_resolvable =
        host.contains('.') || host.contains(':') || host.eq_ignore_ascii_case("localhost");
    if host.is_empty() || !host_resolvable {
        bail!("GITLAB_URL_INVALID: the instance address has no usable host");
    }
    Ok(with_scheme.trim_end_matches('/').to_string())
}

fn encode_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for b in seg.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The API takes the whole path as one `:project_path` segment with `/`
/// encoded as `%2F`; segments may carry other chars (e.g. a username) that
/// get percent-encoded individually.
fn encode_project_path(path: &str) -> String {
    path.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("%2F")
}

fn request(
    client: &reqwest::blocking::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
) -> reqwest::blocking::RequestBuilder {
    client
        .request(method, url)
        .header("PRIVATE-TOKEN", token)
        .header("Accept", "application/json")
}

/// Validate the PAT, then ensure the backup project exists. A bare name
/// (e.g. `skills-manager-backup`) resolves to the token owner's personal
/// namespace and is created as a private project when missing; a full path
/// (`group/subgroup/name`) must already exist — group projects are never
/// auto-created.
pub fn connect_backup_project(
    base_url: &str,
    token: &str,
    project_path: &str,
    proxy_url: Option<&str>,
) -> Result<GitlabConnectInfo> {
    let base = normalize_base_url(base_url)?;
    let client = build_http_client(proxy_url, 20);

    // Who owns this token? Also serves as token validation.
    let resp = request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/api/v4/user"),
        token,
    )
    .send()
    .with_context(|| format!("GITLAB_NETWORK: could not reach {base}"))?;
    let username = match resp.status().as_u16() {
        200 => resp.json::<UserResp>().context("Unexpected /user response")?.username,
        401 => bail!("GITLAB_TOKEN_INVALID: GitLab rejected the token (401)"),
        403 => bail!(
            "GITLAB_TOKEN_INVALID: GitLab denied access (403); the token may be expired or lack the 'api'/'read_api' scope"
        ),
        s => bail!("GitLab /user returned HTTP {s}"),
    };

    let personal_namespace = !project_path.contains('/');
    let full_path = if personal_namespace {
        format!("{username}/{project_path}")
    } else {
        project_path.to_string()
    };

    let resp = request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/api/v4/projects/{}", encode_project_path(&full_path)),
        token,
    )
    .send()
    .with_context(|| format!("GITLAB_NETWORK: could not reach {base}"))?;

    let (project_created, project) = match resp.status().as_u16() {
        200 => (
            false,
            resp.json::<ProjectResp>()
                .context("Unexpected project response")?,
        ),
        404 if !personal_namespace => bail!(
            "GITLAB_PROJECT_NOT_FOUND: {full_path} does not exist or the token cannot see it; group projects are never created automatically — create the project on GitLab first, or connect with a bare name"
        ),
        404 => {
            let resp = request(&client, reqwest::Method::POST, &format!("{base}/api/v4/projects"), token)
                .json(&serde_json::json!({
                    "name": project_path,
                    "path": project_path,
                    "visibility": "private",
                    "initialize_with_readme": false,
                    "description": "Skills Manager backup",
                }))
                .send()
                .with_context(|| format!("GITLAB_NETWORK: could not reach {base}"))?;
            match resp.status().as_u16() {
                201 => (
                    true,
                    resp.json::<ProjectResp>()
                        .context("Unexpected create-project response")?,
                ),
                401 => bail!("GITLAB_TOKEN_INVALID: GitLab rejected the token (401)"),
                // PATs without the 'api' scope land here.
                403 => bail!(
                    "GITLAB_SCOPE: the token cannot create the project — it needs the 'api' scope"
                ),
                // Validation failures come back as 400 with the reason in the
                // body: an already-taken path, or a name the user could see
                // but not access (GitLab answers 404 for invisible projects,
                // so the lookup above missed it).
                400 => {
                    let detail = resp
                        .json::<serde_json::Value>()
                        .ok()
                        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
                        .unwrap_or_else(|| "no detail provided".to_string());
                    bail!("GITLAB_PROJECT_REJECTED: GitLab rejected the project: {detail}")
                }
                s => bail!("GitLab create-project returned HTTP {s}"),
            }
        }
        401 => bail!("GITLAB_TOKEN_INVALID: GitLab rejected the token (401)"),
        403 => bail!(
            "GITLAB_SCOPE: the token cannot read this project (403); grant it access to {full_path}"
        ),
        s => bail!("GitLab project lookup returned HTTP {s}"),
    };

    let project_path = project.path_with_namespace;
    let project_private = project
        .visibility
        .as_deref()
        .map(|v| v == "private")
        .unwrap_or(true);
    log::info!(
        "gitlab connect: using project {project_path} (created={project_created}, private={project_private})"
    );
    Ok(GitlabConnectInfo {
        base_url: base.clone(),
        url: format!("{base}/{project_path}.git"),
        username,
        project_path,
        project_created,
        project_private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_normalization() {
        assert_eq!(
            normalize_base_url("  gitlab.example.com ").unwrap(),
            "https://gitlab.example.com"
        );
        assert_eq!(
            normalize_base_url("https://gitlab.example.com/").unwrap(),
            "https://gitlab.example.com"
        );
        assert_eq!(
            normalize_base_url("http://10.0.0.5:8080").unwrap(),
            "http://10.0.0.5:8080"
        );
        assert_eq!(
            normalize_base_url("gitlab.corp.cn/gitlab/").unwrap(),
            "https://gitlab.corp.cn/gitlab"
        );
        assert_eq!(
            normalize_base_url("localhost:9000").unwrap(),
            "https://localhost:9000"
        );
        // Schemes are case-insensitive (RFC 3986).
        assert_eq!(
            normalize_base_url("HTTPS://gitlab.example.com").unwrap(),
            "HTTPS://gitlab.example.com"
        );
        assert!(normalize_base_url("").is_err());
        assert!(normalize_base_url("ftp://gitlab.example.com").is_err());
        assert!(normalize_base_url("no host").is_err());
        // Embedded credentials must be rejected, never normalized around —
        // keeping them would persist the token into the saved remote URL.
        assert!(normalize_base_url("https://oauth2:glpat-x@gitlab.example.com").is_err());
    }

    #[test]
    fn project_path_validation() {
        assert!(is_valid_project_path("skills-manager-backup"));
        assert!(is_valid_project_path("My_Backup.2026"));
        assert!(is_valid_project_path("group/subgroup/team/backup"));
        // Deeply nested groups are uncommon but legal.
        assert!(is_valid_project_path("g/a/b/c/d/e/name"));
        assert!(!is_valid_project_path(""));
        assert!(!is_valid_project_path("a//b"));
        assert!(!is_valid_project_path("/lead"));
        assert!(!is_valid_project_path("trail/"));
        assert!(!is_valid_project_path("."));
        assert!(!is_valid_project_path("a/../b"));
        assert!(!is_valid_project_path("has space"));
        assert!(!is_valid_project_path(&"x".repeat(256)));
        assert!(!is_valid_project_path(&vec!["g"; 21].join("/")));
        // GitLab itself rejects these suffixes on create.
        assert!(!is_valid_project_path("backup.git"));
        assert!(!is_valid_project_path("group/backup.atom"));
        assert!(is_valid_project_path("group/backup.github"));
    }

    #[test]
    fn project_path_encoding() {
        assert_eq!(encode_project_path("group/sub/name"), "group%2Fsub%2Fname");
        // Slashes become %2F; other bytes are percent-encoded, not passed raw.
        assert_eq!(
            encode_project_path("用户/backup"),
            "%E7%94%A8%E6%88%B7%2Fbackup"
        );
        assert_eq!(encode_project_path("plain"), "plain");
    }
}
