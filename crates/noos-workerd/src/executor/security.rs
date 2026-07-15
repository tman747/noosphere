//! Fail-closed sidecar and child-process security policy.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;

/// A private sidecar endpoint. TCP is deliberately restricted to loopback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarEndpoint {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl SidecarEndpoint {
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        if let Some(address) = value.strip_prefix("tcp://") {
            let address: SocketAddr = address
                .parse()
                .map_err(|_| SecurityError::InvalidEndpoint)?;
            if !address.ip().is_loopback() {
                return Err(SecurityError::PublicListener);
            }
            return Ok(Self::Tcp(address));
        }
        if let Some(path) = value.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(SecurityError::InvalidEndpoint);
            }
            #[cfg(unix)]
            return Ok(Self::Unix(PathBuf::from(path)));
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(SecurityError::UnsupportedUnixSocket);
            }
        }
        Err(SecurityError::InvalidEndpoint)
    }

    #[must_use]
    pub fn is_private(&self) -> bool {
        match self {
            Self::Tcp(address) => address.ip().is_loopback(),
            #[cfg(unix)]
            Self::Unix(_) => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    InvalidEndpoint,
    PublicListener,
    UnsupportedUnixSocket,
    InvalidToken,
    RuntimeNetworkArgument,
    RuntimeOutputArgument,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEndpoint => "sidecar endpoint must be tcp://LOOPBACK:PORT or unix://PATH",
            Self::PublicListener => "public sidecar listeners are forbidden",
            Self::UnsupportedUnixSocket => "unix sockets are unsupported on this platform",
            Self::InvalidToken => {
                "sidecar authentication token must be 64 lowercase hex characters"
            }
            Self::RuntimeNetworkArgument => "runtime network/listener arguments are forbidden",
            Self::RuntimeOutputArgument => {
                "runtime output/framing arguments are controlled by the pinned adapter"
            }
        })
    }
}
impl std::error::Error for SecurityError {}

/// Decode a per-boot 256-bit bearer token without ever logging it.
pub fn decode_token(value: &str) -> Result<[u8; 32], SecurityError> {
    crate::hex::decode_hex32(value).ok_or(SecurityError::InvalidToken)
}

/// Constant-work comparison for the fixed-size authentication token.
#[must_use]
pub fn token_matches(expected: &[u8; 32], presented: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// Reject options capable of turning a local inference child into a listener
/// or remote client. The adapter supplies its own fixed argument vocabulary;
/// this check is defense in depth for operator-provided extra arguments.
pub fn validate_runtime_args(args: &[String]) -> Result<(), SecurityError> {
    const FORBIDDEN: &[&str] = &[
        "--host",
        "--port",
        "--listen",
        "--server",
        "--rpc",
        "--url",
        "--proxy",
        "--remote",
        "--download",
        "--model-url",
        "-mu",
        "--docker-repo",
        "-dr",
        "--hf-repo",
        "-hf",
        "-hfr",
        "--hf-file",
        "-hff",
        "--hf-repo-v",
        "-hfv",
        "-hfrv",
        "--hf-file-v",
        "-hffv",
        "--hf-token",
        "-hft",
    ];
    const CONTROLLED_OUTPUT: &[&str] = &[
        "--color",
        "--skip-chat-parsing",
        "--reasoning-format",
        "--verbose-prompt",
        "--show-timings",
        "--no-show-timings",
        "--log-disable",
        "--simple-io",
        "--no-display-prompt",
        "--single-turn",
        "--file",
        "--prompt",
        "-p",
        "-f",
    ];
    if args.iter().any(|arg| {
        FORBIDDEN
            .iter()
            .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
            || arg.starts_with("http://")
            || arg.starts_with("https://")
    }) {
        return Err(SecurityError::RuntimeNetworkArgument);
    }
    if args.iter().any(|arg| {
        CONTROLLED_OUTPUT
            .iter()
            .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
    }) {
        return Err(SecurityError::RuntimeOutputArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_listener_and_runtime_egress_flags() {
        assert_eq!(
            SidecarEndpoint::parse("tcp://0.0.0.0:9807"),
            Err(SecurityError::PublicListener)
        );
        assert!(SidecarEndpoint::parse("tcp://127.0.0.1:9807").is_ok());
        assert_eq!(
            validate_runtime_args(&["--host=example.test".into()]),
            Err(SecurityError::RuntimeNetworkArgument)
        );
        assert_eq!(
            validate_runtime_args(&["https://example.test/model".into()]),
            Err(SecurityError::RuntimeNetworkArgument)
        );
        assert_eq!(
            validate_runtime_args(&["--reasoning-format=deepseek".into()]),
            Err(SecurityError::RuntimeOutputArgument)
        );
    }

    #[test]
    fn auth_token_is_exact() {
        let token = [7_u8; 32];
        assert!(token_matches(&token, &[7_u8; 32]));
        assert!(!token_matches(&token, &[7_u8; 31]));
        let mut changed = [7_u8; 32];
        changed[20] = 8;
        assert!(!token_matches(&token, &changed));
    }
}
