#!/usr/bin/env python3
"""Deterministic, bounded E-WWM-23 laboratory simulator and evidence evaluator.

A PASS is laboratory evidence only. It does not represent a real 30-day pilot,
production custody, rewards, availability certification, or mainnet readiness.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import time
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT_DIR = ROOT / "experiments" / "wwm-web-capacity"
MANIFEST_PATH = EXPERIMENT_DIR / "experiment.json"
DEFAULT_REPORT_PATH = EXPERIMENT_DIR / "local-evidence.json"

REPORT_SCHEMA = "noos/e-wwm-23-evidence/v1"
FIXTURE_SCHEMA = "noos/e-wwm-23-fixture/v1"
EVIDENCE_SCOPE = "DETERMINISTIC_LAB_SIMULATION"
LOCAL_CACHE_ONLY = "PERSONAL_LOCAL_CACHE_ONLY"
SIMULATED_ADVISORY = "SIMULATED_ADVISORY_ONLY"
MASK64 = (1 << 64) - 1


class ExperimentError(ValueError):
    """The manifest or observation fixture is malformed."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ExperimentError(f"{path} must contain a JSON object")
    return value


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = load_object(path)
    if manifest.get("schema") != "noos/registered-experiment/v1" or manifest.get("experiment_id") != "E-WWM-23":
        raise ExperimentError("not the registered E-WWM-23 manifest")
    if manifest.get("status") != "EXPERIMENTAL_OFF_CHAIN":
        raise ExperimentError("E-WWM-23 must remain experimental and off chain")
    return manifest


def qualifying_fixture(manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a deterministic lab fixture that cannot satisfy real-duration."""
    manifest = manifest or load_manifest()
    hosts = []
    for index in range(30):
        hosts.append(
            {
                "origin": f"https://seed-{index:02d}.web-capacity.invalid",
                "provider": f"provider-{index % 5}",
                "region": f"region-{(index // 5) % 3}",
                "control_cluster": f"control-cluster-{index % 5}",
                "authorized": True,
                "license_ok": True,
                "notice_ok": True,
                "hosting_terms_ok": True,
            }
        )
    cohorts = []
    for browser in manifest["required_browsers"]:
        for device in manifest["required_device_modes"]:
            for storage in manifest["required_storage_modes"]:
                cohorts.append(
                    {
                        "browser": browser,
                        "device_mode": device,
                        "storage_mode": storage,
                        "explicit_opt_ins": 25,
                        "deletion_attempts": 25,
                        "deletion_successes": 25,
                        "offline_deletion_attempts": 25,
                        "offline_deletion_successes": 25,
                    }
                )
    return {
        "schema": FIXTURE_SCHEMA,
        "experiment_id": "E-WWM-23",
        "evidence_scope": EVIDENCE_SCOPE,
        "promotion_authorized": False,
        "observation_days": 0,
        "static_hosts": hosts,
        "browser_cohorts": cohorts,
        "activity_before_opt_in": {
            "artifact_downloads": 0,
            "bytes_stored": 0,
            "hash_operations": 0,
            "heartbeats": 0,
            "uploads": 0,
        },
        "browser_controls": {
            "quota_overruns": 0,
            "egress_cap_overruns": 0,
            "deletion_attempts": 300,
            "deletion_successes": 300,
            "offline_deletion_attempts": 300,
            "offline_deletion_successes": 300,
            "covert_enrollments": 0,
            "misleading_consent_events": 0,
            "quota_bypass_events": 0,
            "hidden_background_events": 0,
            "cross_site_identifier_events": 0,
            "unauthorized_hosting_events": 0,
            "simulated_availability_bps": 3500,
            "reported_disposition": LOCAL_CACHE_ONLY,
            "restore_attempts": 120,
            "restore_successes": 120,
        },
        "privacy_controls": {
            "raw_participant_tokens_in_telemetry": 0,
            "raw_ips_in_telemetry": 0,
            "raw_user_agents_in_telemetry": 0,
            "access_log_retention_days": 7,
            "truncated_ip_only": True,
            "coarse_user_agent_only": True,
        },
        "share_admission": {
            "corrupt_admitted": 0,
            "wrong_artifact_admitted": 0,
            "replayed_admitted": 0,
            "wrong_length_admitted": 0,
            "wrong_origin_admitted": 0,
        },
        "drills": {name: True for name in manifest["required_drills"]},
        "production_effects": {
            "custodian_memberships": 0,
            "availability_certificate_signatures": 0,
            "schedulability_contributions": 0,
            "custody_rewards": 0,
            "production_custody": False,
        },
        "isolation": {
            "coordinator_outage_base_chain_continues": True,
            "coordinator_outage_existing_inference_continues": True,
            "artifact_outage_base_chain_continues": True,
            "artifact_outage_existing_inference_continues": True,
            "coordinator_consensus_dependency": False,
            "coordinator_inference_correctness_dependency": False,
            "bounded_queue": True,
            "bounded_state": True,
        },
        "base_chain": {
            "baseline_p95_us": 100000,
            "stressed_p95_us": 104900,
        },
        "reconstruction": {
            "largest_provider_loss_tested": True,
            "random_host_churn_bps": 3000,
            "churn_seed": 230023,
            "canonical_verifier_rejected_poison": True,
            "reconstructed_source_sha256": manifest["model_binding"]["source_sha256"],
        },
        "reviews": {
            "licensing": True,
            "hosting_terms": True,
            "privacy": True,
            "accessibility": True,
            "security": True,
        },
        "claims": {
            "scope": EVIDENCE_SCOPE,
            "production_availability": False,
            "mainnet_ready": False,
            "millions_of_real_websites": False,
            "unavailable_model_schedulable": False,
        },
    }


def simulate_sessions(session_count: int, state_limit: int, queue_limit: int, seed: int = 0xE23) -> dict[str, Any]:
    """Process synthetic churn sessions in constant bounded memory."""
    if session_count < 1 or state_limit < 1 or queue_limit < 1:
        raise ExperimentError("synthetic benchmark bounds must be positive")
    start_ns = time.perf_counter_ns()
    state = bytearray(state_limit)
    counts: Counter[str] = Counter()
    value = seed & MASK64
    rolling = 0xCBF29CE484222325
    peak_state_records = 0
    peak_queue_depth = 0
    for index in range(session_count):
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK64
        bucket = (value >> 32) % 10000
        if bucket < 6200:
            event = "heartbeat"
            event_code = 1
        elif bucket < 7600:
            event = "offer"
            event_code = 2
        elif bucket < 8500:
            event = "eviction"
            event_code = 3
        elif bucket < 9250:
            event = "restore"
            event_code = 4
        elif bucket < 9750:
            event = "revoke"
            event_code = 5
        else:
            event = "error"
            event_code = 6
        counts[event] += 1
        slot = value % state_limit
        state[slot] = (state[slot] + event_code) & 0xFF
        peak_state_records = min(state_limit, max(peak_state_records, index + 1))
        queue_depth = ((value >> 48) % queue_limit) + 1
        peak_queue_depth = max(peak_queue_depth, queue_depth)
        rolling ^= (value ^ (index * 0x9E3779B97F4A7C15) ^ event_code) & MASK64
        rolling = (rolling * 0x100000001B3) & MASK64
    duration_ns = max(1, time.perf_counter_ns() - start_ns)
    stable = {
        "session_count": session_count,
        "seed": seed,
        "event_counts": dict(sorted(counts.items())),
        "rolling_checksum": f"{rolling:016x}",
        "state_limit": state_limit,
        "queue_limit": queue_limit,
        "peak_state_records": peak_state_records,
        "peak_queue_depth": peak_queue_depth,
    }
    return {
        **stable,
        "simulation_sha256": canonical_sha256(stable),
        "runtime_measurement_class": "NONDETERMINISTIC_WALL_CLOCK",
        "measured_duration_ns": duration_ns,
        "measured_sessions_per_second": session_count * 1_000_000_000 // duration_ns,
    }


def _placement_summary(hosts: list[dict[str, Any]], manifest: dict[str, Any], reconstruction: dict[str, Any]) -> dict[str, Any]:
    model = manifest["model_binding"]
    origins = [str(host.get("origin", "")) for host in hosts]
    if not all(origins) or len(origins) != len(set(origins)):
        return {"valid": False, "reason": "missing or duplicate origins"}
    providers: dict[str, list[str]] = defaultdict(list)
    origin_provider: dict[str, str] = {}
    origin_control_cluster: dict[str, str] = {}
    for host in hosts:
        origin = str(host.get("origin", ""))
        provider = str(host.get("provider", ""))
        control_cluster = str(host.get("control_cluster", ""))
        if not provider or not control_cluster:
            return {"valid": False, "reason": "missing provider or control-cluster membership"}
        providers[provider].append(origin)
        origin_provider[origin] = provider
        origin_control_cluster[origin] = control_cluster

    coordinates = model["coordinates"]
    positions = model["positions"]
    provider_names = sorted(providers)
    placements: list[tuple[str, str, str, str]] = []
    provider_copies: Counter[str] = Counter()
    origin_copies: Counter[str] = Counter()
    control_cluster_copies: Counter[str] = Counter()
    for coordinate in range(coordinates):
        selected = [provider_names[(coordinate + offset) % len(provider_names)] for offset in (0, 1, 3)]
        if len(set(selected)) < 3:
            return {"valid": False, "reason": "fewer than three placement providers"}
        coordinate_placements: list[tuple[str, str, str, str]] = []
        for replica, provider in enumerate(selected):
            members = sorted(providers[provider])
            origin = members[(coordinate // len(provider_names) + replica) % len(members)]
            control_cluster = origin_control_cluster[origin]
            coordinate_placements.append(
                (f"{coordinate // positions}:{coordinate % positions}", origin, provider, control_cluster)
            )
        if len({row[3] for row in coordinate_placements}) < 3:
            return {"valid": False, "reason": "fewer than three placement control clusters"}
        for row in coordinate_placements:
            placements.append(row)
            provider_copies[row[2]] += 1
            origin_copies[row[1]] += 1
            control_cluster_copies[row[3]] += 1

    largest_provider = sorted(provider_copies, key=lambda name: (-provider_copies[name], name))[0]
    churn_bps = int(reconstruction.get("random_host_churn_bps", -1))
    churn_count = len(hosts) * churn_bps // 10000
    seed = int(reconstruction.get("churn_seed", 0))
    largest_provider_origins = {
        origin for origin, provider in origin_provider.items() if provider == largest_provider
    }
    churn_candidates = [origin for origin in origins if origin not in largest_provider_origins]
    ranked = sorted(churn_candidates, key=lambda origin: hashlib.sha256(f"{seed}:{origin}".encode()).digest())
    churned = set(ranked[:churn_count])
    unavailable = churned | largest_provider_origins
    surviving: dict[str, int] = defaultdict(int)
    seen: set[tuple[str, str]] = set()
    for coordinate, origin, _provider, _control_cluster in placements:
        if origin not in unavailable and (coordinate, origin) not in seen:
            surviving[coordinate] += 1
            seen.add((coordinate, origin))
    reconstructible_stripes = 0
    minimum_surviving_positions = positions
    for stripe in range(model["stripes"]):
        available_positions = sum(surviving.get(f"{stripe}:{position}", 0) > 0 for position in range(positions))
        minimum_surviving_positions = min(minimum_surviving_positions, available_positions)
        if available_positions >= model["reconstruction_positions"]:
            reconstructible_stripes += 1

    total = len(placements)
    provider_max_bps = max(provider_copies.values(), default=0) * 10000 // max(1, total)
    origin_max_bps = max(origin_copies.values(), default=0) * 10000 // max(1, total)
    control_cluster_max_bps = max(control_cluster_copies.values(), default=0) * 10000 // max(1, total)
    return {
        "valid": True,
        "coordinate_count": coordinates,
        "copies_per_coordinate": 3,
        "share_file_count": total,
        "largest_provider": largest_provider,
        "churned_origin_count": len(churned),
        "provider_max_bps": provider_max_bps,
        "origin_max_bps": origin_max_bps,
        "control_cluster_count": len(control_cluster_copies),
        "control_cluster_max_bps": control_cluster_max_bps,
        "minimum_surviving_positions_per_stripe": minimum_surviving_positions,
        "reconstructible_stripes": reconstructible_stripes,
        "all_stripes_reconstructible": reconstructible_stripes == model["stripes"],
    }


def _check(check_id: str, passed: bool, detail: str, evidence_class: str = EVIDENCE_SCOPE) -> dict[str, Any]:
    return {"id": check_id, "passed": bool(passed), "evidence_class": evidence_class, "detail": detail}


def _all_zero(mapping: dict[str, Any], names: Iterable[str]) -> bool:
    return all(mapping.get(name) == 0 for name in names)


def evaluate_fixture(
    fixture: dict[str, Any], manifest: dict[str, Any], benchmark: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate all registered gates and kill rules without trusting self-reported status."""
    if fixture.get("schema") != FIXTURE_SCHEMA or fixture.get("experiment_id") != "E-WWM-23":
        raise ExperimentError("fixture identity is invalid")
    hosts = fixture.get("static_hosts")
    cohorts = fixture.get("browser_cohorts")
    if not isinstance(hosts, list) or not isinstance(cohorts, list):
        raise ExperimentError("fixture host and browser cohorts must be arrays")
    minimums = manifest["minimums"]
    maximums = manifest["maximums"]
    controls = fixture.get("browser_controls", {})
    privacy = fixture.get("privacy_controls", {})
    admission = fixture.get("share_admission", {})
    production = fixture.get("production_effects", {})
    isolation = fixture.get("isolation", {})
    reconstruction = fixture.get("reconstruction", {})
    reviews = fixture.get("reviews", {})
    claims = fixture.get("claims", {})
    drills = fixture.get("drills", {})
    pre_opt_in = fixture.get("activity_before_opt_in", {})
    base_chain = fixture.get("base_chain", {})

    placement = _placement_summary(hosts, manifest, reconstruction)
    providers = {host.get("provider") for host in hosts if host.get("provider")}
    regions = {host.get("region") for host in hosts if host.get("region")}
    control_clusters = {
        host.get("control_cluster") for host in hosts if host.get("control_cluster")
    }
    expected_cohort_cells = set(
        product(
            manifest["required_browsers"],
            manifest["required_device_modes"],
            manifest["required_storage_modes"],
        )
    )
    cohort_row_counts: Counter[tuple[str, str, str]] = Counter()
    cohort_opt_ins: Counter[tuple[str, str, str]] = Counter()
    cohort_rows_valid = True
    opt_ins = 0
    for row in cohorts:
        if not isinstance(row, dict) or type(row.get("explicit_opt_ins")) is not int:
            cohort_rows_valid = False
            continue
        count = row["explicit_opt_ins"]
        cell = (row.get("browser"), row.get("device_mode"), row.get("storage_mode"))
        if count < 0 or not all(isinstance(item, str) for item in cell):
            cohort_rows_valid = False
            continue
        cohort_row_counts[cell] += 1
        cohort_opt_ins[cell] += count
        opt_ins += count
    missing_cohort_cells = expected_cohort_cells - set(cohort_row_counts)
    duplicate_cohort_cells = {
        cell for cell, count in cohort_row_counts.items() if count != 1
    }
    exact_cohort_matrix = (
        cohort_rows_valid
        and set(cohort_row_counts) == expected_cohort_cells
        and not duplicate_cohort_cells
        and all(cohort_opt_ins[cell] > 0 for cell in expected_cohort_cells)
    )
    baseline = int(base_chain.get("baseline_p95_us", 0))
    stressed = int(base_chain.get("stressed_p95_us", 0))
    degradation_bps = ((stressed - baseline) * 10000 // baseline) if baseline > 0 else 10000

    simulated_availability_bps = int(controls.get("simulated_availability_bps", -1))
    expected_disposition = LOCAL_CACHE_ONLY
    disposition_honest = controls.get("reported_disposition") == expected_disposition

    deletion_complete = (
        controls.get("deletion_attempts", -1) > 0
        and controls.get("deletion_successes") == controls.get("deletion_attempts")
        and controls.get("offline_deletion_attempts", -1) > 0
        and controls.get("offline_deletion_successes") == controls.get("offline_deletion_attempts")
    )
    matrix_deletion_complete = cohort_rows_valid and all(
        cohort.get("deletion_attempts", -1) == cohort.get("explicit_opt_ins")
        and cohort.get("deletion_successes") == cohort.get("deletion_attempts")
        and cohort.get("offline_deletion_attempts", -1) == cohort.get("explicit_opt_ins")
        and cohort.get("offline_deletion_successes") == cohort.get("offline_deletion_attempts")
        for cohort in cohorts
        if isinstance(cohort, dict)
    )
    deletion_complete = deletion_complete and matrix_deletion_complete
    invalid_zero = _all_zero(
        admission,
        ("corrupt_admitted", "wrong_artifact_admitted", "replayed_admitted", "wrong_length_admitted", "wrong_origin_admitted"),
    )
    production_zero = _all_zero(
        production,
        ("custodian_memberships", "availability_certificate_signatures", "schedulability_contributions", "custody_rewards"),
    ) and production.get("production_custody") is False
    all_drills = set(drills) == set(manifest["required_drills"]) and all(drills.values())
    host_reviews = all(
        host.get("authorized") is True
        and host.get("license_ok") is True
        and host.get("notice_ok") is True
        and host.get("hosting_terms_ok") is True
        for host in hosts
    )
    review_approvals = all(reviews.get(name) is True for name in ("licensing", "hosting_terms", "privacy", "accessibility", "security"))
    privacy_passed = (
        _all_zero(
            privacy,
            (
                "raw_participant_tokens_in_telemetry",
                "raw_ips_in_telemetry",
                "raw_user_agents_in_telemetry",
            ),
        )
        and privacy.get("access_log_retention_days", maximums["access_log_retention_days"] + 1)
        <= maximums["access_log_retention_days"]
        and privacy.get("truncated_ip_only") is True
        and privacy.get("coarse_user_agent_only") is True
    )
    reconstruction_passed = (
        reconstruction.get("largest_provider_loss_tested") is True
        and reconstruction.get("random_host_churn_bps") == 3000
        and placement.get("all_stripes_reconstructible") is True
        and reconstruction.get("canonical_verifier_rejected_poison") is True
        and reconstruction.get("reconstructed_source_sha256") == manifest["model_binding"]["source_sha256"]
    )
    outage_isolated = all(
        isolation.get(name) is True
        for name in (
            "coordinator_outage_base_chain_continues",
            "coordinator_outage_existing_inference_continues",
            "artifact_outage_base_chain_continues",
            "artifact_outage_existing_inference_continues",
        )
    )
    bounded = (
        isolation.get("bounded_queue") is True
        and isolation.get("bounded_state") is True
        and benchmark.get("peak_state_records", maximums["synthetic_state_records"] + 1) <= maximums["synthetic_state_records"]
        and benchmark.get("peak_queue_depth", maximums["synthetic_queue_depth"] + 1) <= maximums["synthetic_queue_depth"]
    )

    gates = [
        _check("registered-identity", fixture.get("evidence_scope") == EVIDENCE_SCOPE and fixture.get("promotion_authorized") is False, "laboratory scope is explicit and promotion is disabled"),
        _check("real-duration", False, "not satisfied: deterministic laboratory simulation contains no elapsed public-pilot evidence", "REAL_PUBLIC_PILOT_REQUIRED"),
        _check("static-origin-diversity", placement.get("valid") is True and len(hosts) >= minimums["origins"] and len(providers) >= minimums["providers"] and len(regions) >= minimums["regions"] and len(control_clusters) >= minimums["control_clusters"], f"simulated_origins={len(hosts)} simulated_providers={len(providers)} simulated_regions={len(regions)} simulated_control_clusters={len(control_clusters)}"),
        _check("triple-coordinate-coverage", placement.get("coordinate_count") == manifest["model_binding"]["coordinates"] and placement.get("copies_per_coordinate") >= minimums["copies_per_coordinate"] and placement.get("share_file_count") >= minimums["share_files"], f"simulated_coordinates={placement.get('coordinate_count', 0)} simulated_share_files={placement.get('share_file_count', 0)}"),
        _check("explicit-cross-browser-opt-ins", opt_ins >= minimums["browser_opt_ins"] and exact_cohort_matrix, f"simulated_explicit_opt_ins={opt_ins} required_cells={len(expected_cohort_cells)} missing_cells={len(missing_cohort_cells)} duplicate_cells={len(duplicate_cohort_cells)}"),
        _check("required-failure-drills", all_drills, f"passed_drills={sum(value is True for value in drills.values())}/{len(manifest['required_drills'])}"),
        _check("zero-pre-opt-in-activity", bool(pre_opt_in) and all(value == 0 for value in pre_opt_in.values()), "all pre-consent download, storage, hash, heartbeat, and upload counters are zero"),
        _check("quota-egress-deletion", controls.get("quota_overruns") == 0 and controls.get("egress_cap_overruns") == 0 and deletion_complete, "zero quota/egress overruns and complete online/offline app-owned deletion"),
        _check("privacy-telemetry-retention", privacy_passed, f"access_log_retention_days={privacy.get('access_log_retention_days')} and aggregate telemetry has no raw participant token, IP, or user-agent"),
        _check("invalid-share-rejection", invalid_zero, "corrupt, wrong-artifact, replayed, wrong-length, and wrong-origin admissions are zero"),
        _check("largest-provider-loss-reconstruction", reconstruction_passed, f"simulated surviving minimum={placement.get('minimum_surviving_positions_per_stripe', 0)} positions; canonical source hash matched"),
        _check("browser-restore-observed", controls.get("restore_attempts", 0) > 0 and controls.get("restore_successes") == controls.get("restore_attempts"), f"simulated_restores={controls.get('restore_successes', 0)}/{controls.get('restore_attempts', 0)}"),
        _check("advisory-reporting", disposition_honest, f"simulated_availability_bps={simulated_availability_bps} disposition={controls.get('reported_disposition')}; simulation is always local-cache-only"),
        _check("zero-production-effects", production_zero, "web participants have zero custody, certificate, schedulability, and reward effect"),
        _check("outage-isolation", outage_isolated, "coordinator and artifact outages preserve base-chain and already-available inference continuity"),
        _check("base-chain-p95-isolation", baseline > 0 and degradation_bps < maximums["base_chain_p95_degradation_bps"], f"simulated_base_chain_p95_degradation_bps={degradation_bps}"),
        _check("bounded-synthetic-million", benchmark.get("session_count") >= minimums["synthetic_sessions"] and sum(benchmark.get("event_counts", {}).values()) == benchmark.get("session_count") and bounded, f"sessions={benchmark.get('session_count', 0)} state={benchmark.get('peak_state_records', 0)} queue={benchmark.get('peak_queue_depth', 0)}"),
        _check("license-notice-concentration", host_reviews and placement.get("provider_max_bps", 10000) <= maximums["provider_concentration_bps"] and placement.get("origin_max_bps", 10000) <= maximums["origin_concentration_bps"] and placement.get("control_cluster_max_bps", 10000) <= maximums["control_cluster_concentration_bps"], f"simulated_provider_max_bps={placement.get('provider_max_bps', 10000)} simulated_origin_max_bps={placement.get('origin_max_bps', 10000)} simulated_control_cluster_max_bps={placement.get('control_cluster_max_bps', 10000)}"),
        _check("review-approvals", review_approvals, "licensing, hosting terms, privacy, accessibility, and security reviews passed in the fixture"),
    ]

    correctness_dependency = isolation.get("coordinator_consensus_dependency") is True or isolation.get("coordinator_inference_correctness_dependency") is True
    kill_rules = [
        _check("kill-covert-or-misleading-consent", controls.get("covert_enrollments") == 0 and controls.get("misleading_consent_events") == 0, "no covert enrollment or misleading consent"),
        _check("kill-incomplete-deletion-or-quota-bypass", deletion_complete and controls.get("quota_overruns") == 0 and controls.get("egress_cap_overruns") == 0 and controls.get("quota_bypass_events") == 0, "deletion completed and quota, egress-cap, and bypass counters are zero"),
        _check("kill-hidden-work-or-cross-site-identity", controls.get("hidden_background_events") == 0 and controls.get("cross_site_identifier_events") == 0, "no hidden background work or cross-site identifier"),
        _check("kill-unauthorized-hosting", controls.get("unauthorized_hosting_events") == 0 and all(host.get("authorized") is True for host in hosts), "all host resources are authorized"),
        _check("kill-false-production-claim", claims.get("scope") == EVIDENCE_SCOPE and claims.get("production_availability") is False and claims.get("mainnet_ready") is False and claims.get("millions_of_real_websites") is False, "claims remain bounded to a deterministic laboratory simulation"),
        _check("kill-unavailable-remains-schedulable", claims.get("unavailable_model_schedulable") is False, "unavailable model is never reported schedulable"),
        _check("kill-corrupt-share-or-reconstruction-failure", invalid_zero and reconstruction_passed, "no invalid share admitted and declared reconstruction succeeded"),
        _check("kill-base-chain-degradation", baseline > 0 and degradation_bps < maximums["base_chain_p95_degradation_bps"], f"degradation_bps={degradation_bps}, kill threshold is {maximums['base_chain_p95_degradation_bps']}"),
        _check("kill-unbounded-or-correctness-dependency", bounded and not correctness_dependency, "bounded state/queues and no coordinator consensus or inference-correctness dependency"),
        _check("kill-advisory-overclaim", disposition_honest, "laboratory availability is reported as simulation and demoted to personal local cache"),
        _check("kill-legal-privacy-accessibility-security", host_reviews and review_approvals and privacy_passed, "all legal, hosting, privacy, accessibility, security, and telemetry-retention checks pass"),
    ]

    gate_ids = [item["id"] for item in gates]
    kill_ids = [item["id"] for item in kill_rules]
    if gate_ids != manifest["gate_ids"] or kill_ids != manifest["kill_rule_ids"]:
        raise ExperimentError("evaluator checks diverge from registered manifest")
    killed = any(not item["passed"] for item in kill_rules)
    failed_non_duration = any(not item["passed"] for item in gates if item["id"] != "real-duration")
    status = "KILLED" if killed else ("FAIL" if failed_non_duration else "LAB_PASS_REAL_PILOT_PENDING")
    browser_disposition = LOCAL_CACHE_ONLY
    return {
        "status": status,
        "browser_disposition": browser_disposition,
        "gates": gates,
        "kill_rules": kill_rules,
        "metrics": {
            "simulated_observation_days": fixture.get("observation_days", 0),
            "required_real_pilot_duration_days": manifest["duration_days"],
            "real_observation_days": 0,
            "simulated_origins": len(hosts),
            "simulated_providers": len(providers),
            "simulated_regions": len(regions),
            "simulated_control_clusters": len(control_clusters),
            "simulated_explicit_browser_opt_ins": opt_ins,
            "simulated_base_chain_p95_degradation_bps": degradation_bps,
            "simulated_browser_availability_bps": simulated_availability_bps,
            "simulated_restore_attempts": controls.get("restore_attempts", 0),
            "simulated_restore_successes": controls.get("restore_successes", 0),
            "simulated_placement": placement,
        },
    }


def build_report(fixture: dict[str, Any], manifest: dict[str, Any], benchmark: dict[str, Any]) -> dict[str, Any]:
    evaluation = evaluate_fixture(fixture, manifest, benchmark)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "experiment_id": "E-WWM-23",
        "contract_identity": manifest["contract_identity"],
        "status": evaluation["status"],
        "evidence_scope": EVIDENCE_SCOPE,
        "production_claim": False,
        "promotion_authorized": False,
        "browser_disposition": evaluation["browser_disposition"],
        "manifest_sha256": canonical_sha256(manifest),
        "fixture_sha256": canonical_sha256(fixture),
        "model_binding": copy.deepcopy(manifest["model_binding"]),
        "gates": evaluation["gates"],
        "kill_rules": evaluation["kill_rules"],
        "metrics": evaluation["metrics"],
        "synthetic_benchmark": benchmark,
        "limitations": [
            "This report is a deterministic laboratory simulation, not evidence of a real 30-day public pilot.",
            "Coordinate reconstruction is simulated from registered RS geometry; this run does not read or reconstruct the 3.8 GB GGUF.",
            "Web participants remain unrewarded, non-custodial, advisory, and unable to affect certificates or production schedulability.",
            "LAB_PASS_REAL_PILOT_PENDING authorizes no production, mainnet, DNS, reward, advisory-capacity, or millions-of-websites claim.",
        ],
    }
    report["evidence_sha256"] = canonical_sha256(report)
    return report


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(report))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--fixture", type=Path, help="optional observation fixture; default is a non-promoting deterministic lab fixture")
    parser.add_argument("--sessions", type=int, default=None, help="synthetic sessions; qualifying minimum is one million")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args(argv)

    manifest = load_manifest(args.manifest)
    fixture = load_object(args.fixture) if args.fixture else qualifying_fixture(manifest)
    sessions = args.sessions if args.sessions is not None else manifest["minimums"]["synthetic_sessions"]
    benchmark = simulate_sessions(
        sessions,
        manifest["maximums"]["synthetic_state_records"],
        manifest["maximums"]["synthetic_queue_depth"],
    )
    report = build_report(fixture, manifest, benchmark)
    write_report(args.output, report)
    print(canonical_bytes({
        "status": report["status"],
        "output": str(args.output),
        "evidence_sha256": report["evidence_sha256"],
        "sessions": benchmark["session_count"],
        "measured_duration_ns": benchmark["measured_duration_ns"],
        "simulation_sha256": benchmark["simulation_sha256"],
    }).decode("utf-8"), end="")
    return 0 if report["status"] == "LAB_PASS_REAL_PILOT_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
