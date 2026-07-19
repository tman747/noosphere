//! Live custodian admission checks for the frozen 12/9/8 Bonsai law.

use crate::config::ExecutorConfig;
use crate::hex::encode_hex;
use noos_cli::wwm_client::CustodianEndpoint;
use noos_da::{ArtifactManifestV1, ARTIFACT_SHARE_BYTES};
use std::collections::BTreeSet;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POSITION_COUNT: usize = 12;
const SCHEDULABLE_MINIMUM: usize = 9;
const CACHE_TTL: Duration = Duration::from_secs(1);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MAP_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilitySnapshot {
    pub live_positions: Vec<u8>,
    pub offline_positions: Vec<u8>,
}

impl AvailabilitySnapshot {
    #[must_use]
    pub fn schedulable(&self) -> bool {
        self.live_positions.len() >= SCHEDULABLE_MINIMUM
    }
}

#[derive(Clone)]
pub struct AvailabilityGate {
    manifest_root: Arc<str>,
    probes: Arc<Vec<PositionProbe>>,
    cache: Arc<Mutex<Option<(Instant, AvailabilitySnapshot)>>>,
    forced: Option<AvailabilitySnapshot>,
}

#[derive(Clone)]
struct PositionProbe {
    position: u8,
    base_url: String,
    expected_etag: String,
}

impl AvailabilityGate {
    pub fn load(config: &ExecutorConfig) -> Result<Self, String> {
        let map_metadata = fs::metadata(&config.model.custodian_map_path)
            .map_err(|error| format!("custodian map metadata: {error}"))?;
        if map_metadata.len() > MAX_MAP_BYTES {
            return Err("custodian map exceeds 64 KiB".into());
        }
        let map_bytes = fs::read(&config.model.custodian_map_path)
            .map_err(|error| format!("custodian map read: {error}"))?;
        let endpoints: Vec<CustodianEndpoint> = serde_json::from_slice(&map_bytes)
            .map_err(|error| format!("custodian map JSON: {error}"))?;
        if endpoints.len() != POSITION_COUNT {
            return Err("serving admission requires all twelve registered endpoints".into());
        }

        let manifest_bytes = fs::read(&config.model.manifest_path)
            .map_err(|error| format!("artifact manifest read: {error}"))?;
        let manifest = ArtifactManifestV1::from_canonical_bytes(&manifest_bytes)
            .map_err(|error| format!("artifact manifest: {error}"))?;
        manifest
            .validate_bonsai_geometry()
            .map_err(|error| format!("artifact manifest geometry: {error}"))?;
        let actual_root = encode_hex(manifest.manifest_root().as_bytes());
        if actual_root != config.model.manifest_root_hex {
            return Err("artifact manifest root does not match executor config".into());
        }
        let first_stripe = manifest
            .stripes
            .first()
            .ok_or_else(|| "artifact manifest has no stripes".to_string())?;
        let mut positions = BTreeSet::new();
        let mut probes = Vec::with_capacity(POSITION_COUNT);
        for endpoint in endpoints {
            let position = usize::from(endpoint.position);
            if position >= POSITION_COUNT || !positions.insert(endpoint.position) {
                return Err("custodian admission positions must be unique and in range".into());
            }
            probes.push(PositionProbe {
                position: endpoint.position,
                base_url: endpoint.base_url.trim_end_matches('/').to_owned(),
                expected_etag: format!(
                    "\"{}\"",
                    encode_hex(first_stripe.shares[position].share_digest.as_bytes())
                ),
            });
        }
        probes.sort_by_key(|probe| probe.position);
        Ok(Self {
            manifest_root: Arc::from(config.model.manifest_root_hex.as_str()),
            probes: Arc::new(probes),
            cache: Arc::new(Mutex::new(None)),
            forced: None,
        })
    }

    #[cfg(test)]
    pub fn schedulable_fixture() -> Self {
        Self {
            manifest_root: Arc::from("fixture"),
            probes: Arc::new(Vec::new()),
            cache: Arc::new(Mutex::new(None)),
            forced: Some(AvailabilitySnapshot {
                live_positions: (0_u8..12).collect(),
                offline_positions: Vec::new(),
            }),
        }
    }

    pub fn snapshot(&self) -> AvailabilitySnapshot {
        if let Some(snapshot) = &self.forced {
            return snapshot.clone();
        }
        if let Ok(cache) = self.cache.lock() {
            if let Some((observed, snapshot)) = cache.as_ref() {
                if observed.elapsed() < CACHE_TTL {
                    return snapshot.clone();
                }
            }
        }
        let mut observations = Vec::with_capacity(self.probes.len());
        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(self.probes.len());
            for probe in self.probes.iter() {
                let manifest_root = self.manifest_root.clone();
                handles.push((
                    probe.position,
                    scope.spawn(move || probe_position(probe, &manifest_root)),
                ));
            }
            for (position, handle) in handles {
                observations.push((position, handle.join().unwrap_or(false)));
            }
        });
        observations.sort_by_key(|(position, _)| *position);
        let snapshot = AvailabilitySnapshot {
            live_positions: observations
                .iter()
                .filter_map(|(position, live)| live.then_some(*position))
                .collect(),
            offline_positions: observations
                .iter()
                .filter_map(|(position, live)| (!live).then_some(*position))
                .collect(),
        };
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some((Instant::now(), snapshot.clone()));
        }
        snapshot
    }

    pub fn require_schedulable(&self) -> Result<AvailabilitySnapshot, AvailabilitySnapshot> {
        let snapshot = self.snapshot();
        if snapshot.schedulable() {
            Ok(snapshot)
        } else {
            Err(snapshot)
        }
    }
}

fn probe_position(probe: &PositionProbe, manifest_root: &str) -> bool {
    let url = format!(
        "{}/artifacts/{manifest_root}/shares/0/{}",
        probe.base_url, probe.position
    );
    let Ok(response) = attohttpc::head(&url)
        .header("Accept", "application/octet-stream")
        .follow_redirects(false)
        .timeout(PROBE_TIMEOUT)
        .send()
    else {
        return false;
    };
    if response.status().as_u16() != 200 {
        return false;
    }
    let headers = response.headers();
    headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        == Some(ARTIFACT_SHARE_BYTES)
        && headers
            .get("accept-ranges")
            .and_then(|value| value.to_str().ok())
            == Some("bytes")
        && headers.get("etag").and_then(|value| value.to_str().ok())
            == Some(probe.expected_etag.as_str())
}
