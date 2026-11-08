//! Minimal Gitee REST (OpenAPI v5) client for the guided backup setup:
//! validate a personal access token (私人令牌), then find the backup
//! repository — creating it as a private repo under the token owner's
//! personal namespace when the input is a bare name. Gitee has no Device
//! Flow, so a PAT is the only guided auth path; the token itself never
//! appears in URLs, logs, or error messages — it travels in the
//! `Authorization: Bearer` header and callers store it in the OS keychain.
//!
//! Errors carry stable prefixes (`GITEE_TOKEN_INVALID`, `GITEE_SCOPE`,
//! `GITEE_REPO_NOT_FOUND`, `GITEE_REPO_REJECTED`, `GITEE_PATH_INVALID`,
//! `GITEE_NETWORK`) the frontend maps to plain-language copy.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::skillssh_api::build_http_client;

pub const API_BASE: &str = "https://gitee.com/api/v5";

#[derive(Debug, Clone, serde::Serialize)]
pub struct GiteeConnectInfo {
    pub username: String,
    /// Full repo path (`owner/repo`).
    pub repo_path: String,
    /// Credential-free HTTPS clone URL.
    pub url: String,
    pub repo_created: bool,
    /// False when the connected repository is not private — the UI warns;
    /// app-created repositories are always private. A missing field is
    /// treated as private so a parsing gap can only suppress the warning.
    pub repo_private: bool,
}

#[derive(Deserialize)]
struct UserResp {
    login: String,
}

#[derive(Deserialize)]
struct OwnerResp {
    login: String,
}

#[derive(Deserialize)]
struct RepoResp {
    path: String,
    owner: OwnerResp,
    private: Option<bool>,
}

/// Gitee repository name / path-segment rules (GitHub-compatible subset):
/// ASCII letters, digits, `-`, `_`, `.`; no empty/`.`/`..` segments, max 100
/// chars. A bare single segment targets the token owner's personal namespace;
/// a two-segment `owner/repo` addresses an existing repository under that
/// owner — Gitee has no nested group paths, so deeper paths are invalid.
pub fn is_valid_repo_name(name: &str) -> bool {
    valid_segment(name)
}

pub fn is_valid_repo_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    segments.len() <= 2 && segments.iter().all(|seg| valid_segment(seg))
}

fn valid_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg.len() <= 100
        && seg != "."
        && seg != ".."
        && seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// A bare name targets the token owner's personal namespace; a full
/// `owner/repo` path passes through untouched.
fn resolve_repo_path(username: &str, repo_input: &str) -> String {
    if repo_input.contains('/') {
        repo_input.to_string()
    } else {
        format!("{username}/{repo_input}")
    }
}

fn request(
    client: &reqwest::blocking::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
) -> reqwest::blocking::RequestBuilder {
    client
        .request(method, url)
        // Header auth, never the `access_token` query param: a query string
        // would leak the token into reqwest error text and logs.
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
}

/// Validate the PAT, then ensure the backup repository exists. A bare name
/// (e.g. `skills-manager-backup`) resolves to the token owner's personal
/// namespace and is created as a private repository when missing; a full
/// path (`owner/repo`) must already exist — other namespaces (orgs, other
/// users) are never auto-created.
pub fn connect_backup_repo(
    token: &str,
    repo_input: &str,
    proxy_url: Option<&str>,
) -> Result<GiteeConnectInfo> {
    let client = build_http_client(proxy_url, 20);

    // Who owns this token? Also serves as token validation.
    let resp = request(&client, reqwest::Method::GET, &format!("{API_BASE}/user"), token)
        .send()
        .context("GITEE_NETWORK: could not reach gitee.com")?;
    let username = match resp.status().as_u16() {
        200 => resp.json::<UserResp>().context("Unexpected /user response")?.login,
        401 => bail!("GITEE_TOKEN_INVALID: Gitee rejected the token (401)"),
        403 => bail!(
            "GITEE_TOKEN_INVALID: Gitee denied access (403); the token may be expired or lack the 'user_info' scope"
        ),
        s => bail!("Gitee /user returned HTTP {s}"),
    };

    let personal_namespace = !repo_input.contains('/');
    let full_path = resolve_repo_path(&username, repo_input);

    let resp = request(
        &client,
        reqwest::Method::GET,
        &format!("{API_BASE}/repos/{full_path}"),
        token,
    )
    .send()
    .context("GITEE_NETWORK: could not reach gitee.com")?;

    let (repo_created, repo) = match resp.status().as_u16() {
        200 => (
            false,
            resp.json::<RepoResp>().context("Unexpected repo response")?,
        ),
        404 if !personal_namespace => bail!(
            "GITEE_REPO_NOT_FOUND: {full_path} does not exist or the token cannot see it; repositories under other owners are never created automatically — create it on Gitee first, or connect with a bare name"
        ),
        404 => {
            let name = repo_input;
            let resp = request(&client, reqwest::Method::POST, &format!("{API_BASE}/user/repos"), token)
                .json(&serde_json::json!({
                    "name": name,
                    "private": true,
                    "auto_init": false,
                    "description": "Skills Manager backup",
                }))
                .send()
                .context("GITEE_NETWORK: could not reach gitee.com")?;
            match resp.status().as_u16() {
                201 => (
                    true,
                    resp.json::<RepoResp>()
                        .context("Unexpected create-repo response")?,
                ),
                401 => bail!("GITEE_TOKEN_INVALID: Gitee rejected the token (401)"),
                // Tokens without the 'projects' scope land here.
                403 => bail!(
                    "GITEE_SCOPE: the token cannot create the repository — it needs the 'projects' scope"
                ),
                // Validation failures come back as 400 with the reason in the
                // body: an already-taken name, or a name Gitee reserves.
                400 => {
                    let detail = resp
                        .json::<serde_json::Value>()
                        .ok()
                        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
                        .unwrap_or_else(|| "no detail provided".to_string());
                    bail!("GITEE_REPO_REJECTED: Gitee rejected the repository: {detail}")
                }
                s => bail!("Gitee create-repo returned HTTP {s}"),
            }
        }
        401 => bail!("GITEE_TOKEN_INVALID: Gitee rejected the token (401)"),
        403 => bail!(
            "GITEE_SCOPE: the token cannot read this repository (403); grant it access to {full_path}"
        ),
        s => bail!("Gitee repo lookup returned HTTP {s}"),
    };

    let repo_path = format!("{}/{}", repo.owner.login, repo.path);
    let repo_private = repo.private.unwrap_or(true);
    log::info!(
        "gitee connect: using repo {repo_path} (created={repo_created}, private={repo_private})"
    );
    Ok(GiteeConnectInfo {
        url: format!("https://gitee.com/{repo_path}.git"),
        username,
        repo_path,
        repo_created,
        repo_private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_validation() {
        assert!(is_valid_repo_name("skills-manager-backup"));
        assert!(is_valid_repo_name("My_Backup.2026"));
        assert!(!is_valid_repo_name(""));
        assert!(!is_valid_repo_name("."));
        assert!(!is_valid_repo_name(".."));
        assert!(!is_valid_repo_name("has space"));
        assert!(!is_valid_repo_name("a/b"));
        assert!(!is_valid_repo_name(&"x".repeat(101)));
    }

    #[test]
    fn repo_path_validation() {
        assert!(is_valid_repo_path("owner/repo"));
        assert!(is_valid_repo_path("skills-manager-backup"));
        // Gitee has no nested group paths — deeper segments are invalid.
        assert!(!is_valid_repo_path("a/b/c"));
        assert!(!is_valid_repo_path(""));
        assert!(!is_valid_repo_path("a//b"));
        assert!(!is_valid_repo_path("/lead"));
        assert!(!is_valid_repo_path("trail/"));
        assert!(!is_valid_repo_path("a/../b"));
        assert!(!is_valid_repo_path("has space/repo"));
        assert!(!is_valid_repo_path("owner/has space"));
        assert!(!is_valid_repo_path("owner/no-such-repo!"));
    }

    #[test]
    fn full_path_resolution() {
        // Bare names resolve to the token owner's namespace; full paths pass
        // through untouched.
        assert_eq!(
            resolve_repo_path("tianyi", "skills-manager-backup"),
            "tianyi/skills-manager-backup"
        );
        assert_eq!(
            resolve_repo_path("tianyi", "some-org/repo"),
            "some-org/repo"
        );
    }
}
