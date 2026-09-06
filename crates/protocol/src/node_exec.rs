use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const SYSTEM_EXEC_COMMAND: &str = "system.exec.v1";

/// Versioned request for executing a process on a paired node.
///
/// Arguments remain separate across the wire so the node never needs to invoke
/// a shell or reconstruct a command string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemExecRequest {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    pub timeout_ms: u64,
}

pub const SAFE_ENV_ALLOWLIST: &[&str] = &["TERM", "LANG", "COLORTERM", "NO_COLOR", "FORCE_COLOR"];
pub const SAFE_ENV_PREFIX_ALLOWLIST: &[&str] = &["LC_"];

#[must_use]
pub fn is_safe_remote_env_key(key: &str) -> bool {
    is_valid_env_key(key)
        && (SAFE_ENV_ALLOWLIST.contains(&key)
            || SAFE_ENV_PREFIX_ALLOWLIST
                .iter()
                .any(|prefix| key.starts_with(prefix)))
}

#[must_use]
pub fn filter_remote_env(env: &HashMap<String, String>) -> HashMap<String, String> {
    env.iter()
        .filter(|(key, _)| is_safe_remote_env_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[must_use]
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_preserves_argument_boundaries() {
        let value = serde_json::json!({
            "program": "/usr/bin/printf",
            "args": ["a b", "; touch /tmp/nope", "$(id)", "*", "x&&y"],
            "timeoutMs": 1000,
        });

        let request: SystemExecRequest = serde_json::from_value(value).unwrap();
        assert_eq!(request.args, [
            "a b",
            "; touch /tmp/nope",
            "$(id)",
            "*",
            "x&&y"
        ]);
    }

    #[test]
    fn legacy_shell_command_is_rejected() {
        let value = serde_json::json!({
            "command": "echo hello; id",
            "timeoutMs": 1000,
        });

        assert!(serde_json::from_value::<SystemExecRequest>(value).is_err());
    }

    #[test]
    fn remote_environment_is_allowlisted() {
        let env = HashMap::from([
            ("TERM".into(), "xterm".into()),
            ("LC_ALL".into(), "C".into()),
            ("LC_$(id)".into(), "bad".into()),
            ("PATH".into(), "/tmp".into()),
            ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
            ("NODE_OPTIONS".into(), "--require=/tmp/evil".into()),
        ]);

        let filtered = filter_remote_env(&env);
        assert_eq!(filtered.get("TERM").map(String::as_str), Some("xterm"));
        assert_eq!(filtered.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(filtered.len(), 2);
    }
}
