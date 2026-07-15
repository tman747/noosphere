use super::model::{ExecutionRequest, ExecutionResult, ExecutorRegistration, FinalizedResolution};
use async_trait::async_trait;
use reqwest::{redirect::Policy, Client, Url};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    NoRegisteredExecutor,
    InvalidRegisteredOrigin,
    Transport(String),
    Rejected(String),
}

#[async_trait]
pub trait ExecutorDispatcher: Send + Sync {
    async fn execute(
        &self,
        registration: &ExecutorRegistration,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, DispatchError>;

    async fn cancel(
        &self,
        registration: &ExecutorRegistration,
        job_id: &str,
    ) -> Result<(), DispatchError>;
}

#[derive(Clone)]
pub struct RegisteredHttpDispatcher {
    client: Client,
    allowed_origins: BTreeSet<String>,
    allow_loopback_for_tests: bool,
}

impl RegisteredHttpDispatcher {
    pub fn new(
        registered: &[ExecutorRegistration],
        timeout: Duration,
        allow_loopback_for_tests: bool,
    ) -> Result<Self, DispatchError> {
        let mut allowed_origins = BTreeSet::new();
        for edge in registered {
            validate_origin(&edge.https_origin, allow_loopback_for_tests)?;
            allowed_origins.insert(edge.https_origin.trim_end_matches('/').to_owned());
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|error| DispatchError::Transport(error.to_string()))?;
        Ok(Self {
            client,
            allowed_origins,
            allow_loopback_for_tests,
        })
    }

    fn endpoint(
        &self,
        registration: &ExecutorRegistration,
        suffix: &str,
    ) -> Result<Url, DispatchError> {
        let origin = registration.https_origin.trim_end_matches('/');
        if !registration.active
            || registration.protocol_version != 2
            || !self.allowed_origins.contains(origin)
        {
            return Err(DispatchError::NoRegisteredExecutor);
        }
        validate_origin(origin, self.allow_loopback_for_tests)?;
        Url::parse(&format!("{origin}{suffix}")).map_err(|_| DispatchError::InvalidRegisteredOrigin)
    }
}

#[derive(Serialize)]
struct EdgeExecuteRequest<'a> {
    schema: &'static str,
    job_id: &'a str,
    capsule_id: &'a str,
    execution_profile_id: &'a str,
    prompt: &'a str,
    maximum_output_tokens: u32,
    prompt_commitment: &'a str,
}

#[derive(Deserialize)]
struct EdgeError {
    error: String,
}

#[async_trait]
impl ExecutorDispatcher for RegisteredHttpDispatcher {
    async fn execute(
        &self,
        registration: &ExecutorRegistration,
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, DispatchError> {
        let url = self.endpoint(registration, "/internal/wwm/v2/execute")?;
        let response = self
            .client
            .post(url)
            .header("x-noos-executor-id", &registration.executor_id)
            .json(&EdgeExecuteRequest {
                schema: "noos/executor-dispatch/v2",
                job_id: &request.job_id,
                capsule_id: &request.capsule_id,
                execution_profile_id: &request.execution_profile_id,
                prompt: &request.prompt,
                maximum_output_tokens: request.maximum_output_tokens,
                prompt_commitment: &request.prompt_commitment,
            })
            .send()
            .await
            .map_err(|error| DispatchError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response
                .json::<EdgeError>()
                .await
                .map(|value| value.error)
                .unwrap_or_else(|_| status.to_string());
            return Err(DispatchError::Rejected(detail));
        }
        response
            .json::<ExecutionResult>()
            .await
            .map_err(|error| DispatchError::Transport(error.to_string()))
    }

    async fn cancel(
        &self,
        registration: &ExecutorRegistration,
        job_id: &str,
    ) -> Result<(), DispatchError> {
        let url = self.endpoint(
            registration,
            &format!("/internal/wwm/v2/jobs/{job_id}/cancel"),
        )?;
        let response = self
            .client
            .post(url)
            .header("x-noos-executor-id", &registration.executor_id)
            .send()
            .await
            .map_err(|error| DispatchError::Transport(error.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(DispatchError::Rejected(response.status().to_string()))
        }
    }
}

pub fn select_registered_executor(
    resolution: &FinalizedResolution,
    job_id: &str,
) -> Result<ExecutorRegistration, DispatchError> {
    let mut eligible = resolution
        .executors
        .iter()
        .filter(|edge| edge.active && edge.protocol_version == 2)
        .cloned()
        .collect::<Vec<_>>();
    eligible.sort_by(|left, right| left.executor_id.cmp(&right.executor_id));
    if eligible.is_empty() {
        return Err(DispatchError::NoRegisteredExecutor);
    }
    let digest = blake3::hash(job_id.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest.as_bytes()[..8]);
    let index = usize::try_from(u64::from_le_bytes(prefix)).unwrap_or(0) % eligible.len();
    Ok(eligible.swap_remove(index))
}

fn validate_origin(value: &str, allow_loopback_for_tests: bool) -> Result<(), DispatchError> {
    let parsed = Url::parse(value).map_err(|_| DispatchError::InvalidRegisteredOrigin)?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(DispatchError::InvalidRegisteredOrigin);
    }
    let host = parsed
        .host_str()
        .ok_or(DispatchError::InvalidRegisteredOrigin)?;
    let loopback = host
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(host.eq_ignore_ascii_case("localhost"));
    if parsed.scheme() != "https"
        && !(allow_loopback_for_tests && parsed.scheme() == "http" && loopback)
    {
        return Err(DispatchError::InvalidRegisteredOrigin);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if (ip.is_loopback() || ip.is_unspecified() || is_private(ip)) && !allow_loopback_for_tests
        {
            return Err(DispatchError::InvalidRegisteredOrigin);
        }
    }
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => value.is_private() || value.is_link_local() || value.is_broadcast(),
        IpAddr::V6(value) => value.is_unique_local() || value.is_unicast_link_local(),
    }
}
