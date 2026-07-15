use axum::http::{header, HeaderMap, HeaderValue, Method};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantIdentity {
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct TenantCredential {
    pub tenant_id: String,
    pub bearer_token: String,
    pub csrf_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    credentials: BTreeMap<[u8; 32], TenantCredential>,
    allowed_origins: BTreeSet<String>,
    pub trust_forwarded_headers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Unauthorized,
    Csrf,
    Cors,
    UntrustedProxy,
    RequestSmuggling,
    InvalidTenant,
}

impl SecurityConfig {
    pub fn new(
        credentials: Vec<TenantCredential>,
        allowed_origins: impl IntoIterator<Item = String>,
        trust_forwarded_headers: bool,
    ) -> Result<Self, AuthError> {
        let mut indexed = BTreeMap::new();
        for credential in credentials {
            if !valid_tenant(&credential.tenant_id)
                || credential.bearer_token.len() < 32
                || credential.bearer_token.len() > 512
                || indexed
                    .insert(token_hash(&credential.bearer_token), credential)
                    .is_some()
            {
                return Err(AuthError::InvalidTenant);
            }
        }
        if indexed.is_empty() {
            return Err(AuthError::Unauthorized);
        }
        let allowed_origins = allowed_origins.into_iter().collect::<BTreeSet<_>>();
        if allowed_origins
            .iter()
            .any(|origin| !valid_origin(origin) || origin == "*")
        {
            return Err(AuthError::Cors);
        }
        Ok(Self {
            credentials: indexed,
            allowed_origins,
            trust_forwarded_headers,
        })
    }

    pub fn authenticate(
        &self,
        method: &Method,
        headers: &HeaderMap,
    ) -> Result<TenantIdentity, AuthError> {
        self.validate_transport_headers(headers)?;
        self.validate_origin(headers)?;
        let authorization = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        let cookie_token = cookie(headers, "wwm_session");
        let (token, cookie_mode) = match authorization {
            Some(value) if value.starts_with("Bearer ") => (&value[7..], false),
            Some(_) => return Err(AuthError::Unauthorized),
            None => (cookie_token.ok_or(AuthError::Unauthorized)?, true),
        };
        let credential = self
            .credentials
            .get(&token_hash(token))
            .filter(|candidate| candidate.bearer_token.as_bytes() == token.as_bytes())
            .ok_or(AuthError::Unauthorized)?;
        if cookie_mode && method != Method::GET && method != Method::HEAD {
            let expected = credential.csrf_token.as_deref().ok_or(AuthError::Csrf)?;
            let supplied = headers
                .get("x-csrf-token")
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthError::Csrf)?;
            if token_hash(expected) != token_hash(supplied) {
                return Err(AuthError::Csrf);
            }
            if headers.get(header::ORIGIN).is_none() {
                return Err(AuthError::Csrf);
            }
        }
        Ok(TenantIdentity {
            tenant_id: credential.tenant_id.clone(),
        })
    }

    pub fn validate_public_headers(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        self.validate_transport_headers(headers)?;
        self.validate_origin(headers)
    }

    pub fn apply_cors(&self, request_headers: &HeaderMap, response: &mut HeaderMap) {
        if let Some(origin) = request_headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .filter(|origin| self.allowed_origins.contains(*origin))
        {
            if let Ok(value) = HeaderValue::from_str(origin) {
                response.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
                response.insert(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
                response.insert(header::VARY, HeaderValue::from_static("Origin"));
            }
        }
    }

    fn validate_origin(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        if let Some(origin) = headers.get(header::ORIGIN) {
            let origin = origin.to_str().map_err(|_| AuthError::Cors)?;
            if !self.allowed_origins.contains(origin) {
                return Err(AuthError::Cors);
            }
        }
        Ok(())
    }

    fn validate_transport_headers(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        if headers.contains_key(header::CONTENT_LENGTH)
            && headers.contains_key(header::TRANSFER_ENCODING)
        {
            return Err(AuthError::RequestSmuggling);
        }
        if !self.trust_forwarded_headers
            && [
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
            ]
            .iter()
            .any(|name| headers.contains_key(*name))
        {
            return Err(AuthError::UntrustedProxy);
        }
        Ok(())
    }
}

fn token_hash(value: &str) -> [u8; 32] {
    *blake3::hash(value.as_bytes()).as_bytes()
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
}

fn valid_tenant(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}
