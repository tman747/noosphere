use super::{Result, WebCapacityError};
use async_trait::async_trait;
use futures_util::StreamExt;
use noos_crypto::{hash_domain, verify_domain, DomainId, Keypair, PublicKey, Signature};
use reqwest::{redirect::Policy, Method, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct FetchedResponse {
    pub status: u16,
    pub final_url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait HostFetcher: Send + Sync {
    async fn fetch(&self, url: &str, maximum_bytes: usize) -> Result<FetchedResponse>;

    async fn head(&self, _url: &str, _maximum_bytes: usize) -> Result<FetchedResponse> {
        Err(WebCapacityError::HostFetch(
            "host fetcher does not support HEAD probes".to_owned(),
        ))
    }

    async fn fetch_range(
        &self,
        _url: &str,
        _start: u64,
        _end: u64,
        _maximum_bytes: usize,
    ) -> Result<FetchedResponse> {
        Err(WebCapacityError::HostFetch(
            "host fetcher does not support Range probes".to_owned(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ReqwestHostFetcher {
    timeout: Duration,
    loopback_test_ca: Option<reqwest::Certificate>,
}

impl ReqwestHostFetcher {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            loopback_test_ca: None,
        }
    }

    pub fn new_loopback_test(timeout: Duration, ca_certificate_pem: &[u8]) -> Result<Self> {
        let certificate = reqwest::Certificate::from_pem(ca_certificate_pem).map_err(|error| {
            WebCapacityError::Config(format!("loopback test CA is not valid PEM: {error}"))
        })?;
        Ok(Self {
            timeout,
            loopback_test_ca: Some(certificate),
        })
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        range: Option<(u64, u64)>,
        maximum_bytes: usize,
    ) -> Result<FetchedResponse> {
        if maximum_bytes == 0 {
            return Err(WebCapacityError::HostFetch(
                "zero-byte fetch limit is invalid".to_owned(),
            ));
        }
        let parsed = Url::parse(url)
            .map_err(|_| WebCapacityError::HostFetch("invalid HTTPS URL".to_owned()))?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(WebCapacityError::HostFetch(
                "host fetch requires an absolute credential-free HTTPS URL".to_owned(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| WebCapacityError::HostFetch("URL lacks a host".to_owned()))?;
        let port = parsed.port_or_known_default().ok_or_else(|| {
            WebCapacityError::HostFetch("URL lacks a known HTTPS port".to_owned())
        })?;
        let pinned = if self.loopback_test_ca.is_some() {
            exact_loopback_destination(host, port)?
        } else {
            resolve_public(host, port)
                .await?
                .first()
                .copied()
                .ok_or_else(|| WebCapacityError::Ssrf("host resolved to no addresses".to_owned()))?
        };
        let mut client_builder = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(self.timeout)
            .resolve(host, pinned);
        if let Some(certificate) = &self.loopback_test_ca {
            client_builder = client_builder.add_root_certificate(certificate.clone());
        }
        let client = client_builder
            .build()
            .map_err(|error| WebCapacityError::HostFetch(format!("build HTTP client: {error}")))?;
        let mut request = client
            .request(method, parsed.clone())
            .header("Accept-Encoding", "identity");
        if let Some((start, end)) = range {
            if start > end {
                return Err(WebCapacityError::HostFetch(
                    "Range probe start exceeds its end".to_owned(),
                ));
            }
            request = request.header("Range", format!("bytes={start}-{end}"));
        }
        let response = request
            .send()
            .await
            .map_err(|error| WebCapacityError::HostFetch(format!("HTTPS fetch failed: {error}")))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(WebCapacityError::HostFetch(
                "redirect responses are forbidden".to_owned(),
            ));
        }
        if let Some(length) = response.content_length() {
            if length > maximum_bytes as u64 {
                return Err(WebCapacityError::HostFetch(
                    "declared response length exceeds the endpoint bound".to_owned(),
                ));
            }
        }
        let final_url = response.url().to_string();
        if final_url != parsed.as_str() {
            return Err(WebCapacityError::HostFetch(
                "final URL differs from the requested immutable URL".to_owned(),
            ));
        }
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(maximum_bytes),
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                WebCapacityError::HostFetch(format!("read HTTPS response: {error}"))
            })?;
            if body.len().saturating_add(chunk.len()) > maximum_bytes {
                return Err(WebCapacityError::HostFetch(
                    "response body exceeds the endpoint bound".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchedResponse {
            status,
            final_url,
            headers,
            body,
        })
    }
}

#[async_trait]
impl HostFetcher for ReqwestHostFetcher {
    async fn fetch(&self, url: &str, maximum_bytes: usize) -> Result<FetchedResponse> {
        self.request(Method::GET, url, None, maximum_bytes).await
    }

    async fn head(&self, url: &str, maximum_bytes: usize) -> Result<FetchedResponse> {
        self.request(Method::HEAD, url, None, maximum_bytes).await
    }

    async fn fetch_range(
        &self,
        url: &str,
        start: u64,
        end: u64,
        maximum_bytes: usize,
    ) -> Result<FetchedResponse> {
        self.request(Method::GET, url, Some((start, end)), maximum_bytes)
            .await
    }
}

pub fn canonical_https_origin(value: &str) -> Result<String> {
    let parsed = Url::parse(value)
        .map_err(|_| WebCapacityError::InvalidOrigin("origin is not a URL".to_owned()))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(WebCapacityError::InvalidOrigin(
            "origin must be credential-free HTTPS with no path, query, or fragment".to_owned(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| WebCapacityError::InvalidOrigin("origin lacks a host".to_owned()))?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let canonical = match parsed.port() {
        Some(port) => format!("https://{authority}:{port}"),
        None => format!("https://{authority}"),
    };
    if value != canonical || value.len() > 253 {
        return Err(WebCapacityError::InvalidOrigin(
            "origin is not in canonical lowercase form or names a default port".to_owned(),
        ));
    }
    Ok(canonical)
}

pub fn origin_of_url(value: &str) -> Result<String> {
    let parsed = Url::parse(value)
        .map_err(|_| WebCapacityError::InvalidOrigin("resource URL is invalid".to_owned()))?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(WebCapacityError::InvalidOrigin(
            "resource URL must be credential-free HTTPS without a fragment".to_owned(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| WebCapacityError::InvalidOrigin("resource URL lacks a host".to_owned()))?;
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(match parsed.port() {
        Some(port) => format!("https://{authority}:{port}"),
        None => format!("https://{authority}"),
    })
}

pub fn require_same_origin(url: &str, expected: &str) -> Result<()> {
    if origin_of_url(url)? != expected {
        return Err(WebCapacityError::InvalidOrigin(
            "resource URL leaves the manifest canonical origin".to_owned(),
        ));
    }
    Ok(())
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err(WebCapacityError::InvalidRecord(
                    "floating-point values are forbidden in signed web-capacity records".to_owned(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(text) => {
            let encoded = serde_json::to_string(text).map_err(|error| {
                WebCapacityError::InvalidRecord(format!("encode JSON string: {error}"))
            })?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| utf16_order(left, right));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key).map_err(|error| {
                    WebCapacityError::InvalidRecord(format!("encode JSON key: {error}"))
                })?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn utf16_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub fn sign_json(
    signer: &Keypair,
    domain: DomainId,
    value_without_signature: &Value,
) -> Result<String> {
    let canonical = canonical_json(value_without_signature)?;
    signer
        .sign_domain(domain, &[&canonical])
        .map(|signature| hex::encode(signature.into_bytes()))
        .map_err(|error| WebCapacityError::Crypto(format!("sign record: {error}")))
}

pub fn verify_json_signature(
    domain: DomainId,
    public_key_hex: &str,
    signature_hex: &str,
    value_without_signature: &Value,
) -> Result<()> {
    let public_key = PublicKey::from_bytes(decode_hex32(public_key_hex)?);
    let signature = Signature::from_bytes(decode_hex64(signature_hex)?);
    let canonical = canonical_json(value_without_signature)?;
    verify_domain(domain, &public_key, &[&canonical], &signature)
        .map_err(|_| WebCapacityError::InvalidSignature)
}

pub fn domain_hash_hex(domain: DomainId, parts: &[&[u8]]) -> Result<String> {
    hash_domain(domain, parts)
        .map(|hash| hex::encode(hash.into_bytes()))
        .map_err(|error| WebCapacityError::Crypto(format!("hash record: {error}")))
}

pub fn domain_hash(domain: DomainId, parts: &[&[u8]]) -> Result<[u8; 32]> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|error| WebCapacityError::Crypto(format!("hash record: {error}")))
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WebCapacityError::InvalidRecord(
            "expected canonical lowercase hex32".to_owned(),
        ));
    }
    hex::decode(value)
        .map_err(|_| WebCapacityError::InvalidRecord("invalid hex32".to_owned()))?
        .try_into()
        .map_err(|_| WebCapacityError::InvalidRecord("invalid hex32 length".to_owned()))
}

pub fn decode_hex64(value: &str) -> Result<[u8; 64]> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WebCapacityError::InvalidRecord(
            "expected canonical lowercase Ed25519 signature".to_owned(),
        ));
    }
    hex::decode(value)
        .map_err(|_| WebCapacityError::InvalidRecord("invalid signature hex".to_owned()))?
        .try_into()
        .map_err(|_| WebCapacityError::InvalidRecord("invalid signature length".to_owned()))
}

fn exact_loopback_destination(host: &str, port: u16) -> Result<SocketAddr> {
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let address = literal.parse::<IpAddr>().map_err(|_| {
        WebCapacityError::Ssrf(
            "loopback test transport rejects DNS names and requires a literal address".to_owned(),
        )
    })?;
    if address != IpAddr::V4(Ipv4Addr::LOCALHOST) && address != IpAddr::V6(Ipv6Addr::LOCALHOST) {
        return Err(WebCapacityError::Ssrf(
            "loopback test transport permits only exact 127.0.0.1 or ::1".to_owned(),
        ));
    }
    Ok(SocketAddr::new(address, port))
}

pub fn now_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| WebCapacityError::Internal("system clock precedes Unix epoch".to_owned()))
}

async fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(WebCapacityError::Ssrf(
                "literal destination address is not globally routable".to_owned(),
            ));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| WebCapacityError::HostFetch(format!("resolve host: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(WebCapacityError::Ssrf(
            "destination resolves to an empty, private, loopback, link-local, multicast, or reserved address set"
                .to_owned(),
        ));
    }
    Ok(addresses)
}

#[must_use]
pub fn is_public_ip(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
    {
        return false;
    }
    !(octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || octets[..3] == [192, 0, 0]
        || octets[..3] == [192, 0, 2]
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || octets[..3] == [198, 51, 100]
        || octets[..3] == [203, 0, 113]
        || octets[0] >= 240)
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = address.segments();
    let unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let link_local = (segments[0] & 0xffc0) == 0xfe80;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let discard_only = segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0;
    !(unique_local || link_local || documentation || discard_only)
}
