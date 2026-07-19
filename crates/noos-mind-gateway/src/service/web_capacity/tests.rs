use super::{
    model::{
        ChainBinding, Ed25519Signature, InventoryBinding, InventoryRow, LicenseBinding,
        StaticHostManifest, StaticInventory, StorageClass, TransportPolicy, UploadPolicy,
    },
    security::{
        canonical_https_origin, canonical_json, is_public_ip, now_seconds, HostFetcher,
        ReqwestHostFetcher,
    },
    store::{WebCapacityStore, WebCapacityStoreLimits},
};
use axum::{
    body::Body,
    http::{header, Method, Request},
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Barrier},
    thread,
};
use tempfile::tempdir;

#[test]
fn canonical_origin_is_https_origin_only() {
    assert_eq!(
        canonical_https_origin("https://capacity.example").unwrap(),
        "https://capacity.example"
    );
    assert_eq!(
        canonical_https_origin("https://capacity.example:8443").unwrap(),
        "https://capacity.example:8443"
    );
    for invalid in [
        "http://capacity.example",
        "https://capacity.example/",
        "https://CAPACITY.example",
        "https://capacity.example:443",
        "https://user@capacity.example",
        "https://capacity.example/path",
        "https://capacity.example?query",
        "null",
    ] {
        assert!(
            canonical_https_origin(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn ssrf_filter_rejects_private_reserved_and_documentation_ranges() {
    for rejected in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fc00::1".parse().unwrap(),
        "fe80::1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ] {
        assert!(!is_public_ip(rejected), "accepted {rejected}");
    }
    assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[tokio::test]
async fn default_host_fetcher_still_rejects_loopback_literals_and_dns_resolution() {
    let fetcher = ReqwestHostFetcher::new(std::time::Duration::from_secs(1));
    for url in [
        "https://127.0.0.1:4443/share",
        "https://[::1]:4443/share",
        "https://localhost:4443/share",
    ] {
        let error = fetcher.fetch(url, 1).await.unwrap_err().to_string();
        assert!(
            error.contains("globally routable")
                || error.contains("private, loopback, link-local, multicast, or reserved"),
            "default fetcher did not fail through SSRF resolution for {url}: {error}"
        );
    }
}

#[test]
fn canonical_json_is_ordered_and_forbids_floating_point() {
    let value = json!({"z": [true, null, "x"], "a": 7, "aa": "value"});
    assert_eq!(
        canonical_json(&value).unwrap(),
        br#"{"a":7,"aa":"value","z":[true,null,"x"]}"#
    );
    assert!(canonical_json(&json!({"float": 1.5})).is_err());
}

#[test]
fn sqlite_store_contains_only_off_chain_capacity_tables_and_hashes_sessions() {
    let temp = tempdir().unwrap();
    let database = temp.path().join("capacity.sqlite");
    let store = WebCapacityStore::open(&database).unwrap();
    assert_eq!(
        store.table_names().unwrap(),
        [
            "access_log",
            "assignment_rows",
            "assignments",
            "hosts",
            "inventory",
            "metadata",
            "rate_limits",
            "reports",
            "restore_releases",
            "restore_tasks",
            "restores",
            "sessions",
        ]
    );
    let token_hash = [1_u8; 32];
    let raw_token = "raw-token-must-never-be-persisted";
    store
        .create_session(
            token_hash,
            &"02".repeat(32),
            "https://capacity.example",
            "consent-v1",
            16,
            16 * super::model::SHARE_BYTES,
            StorageClass::Opfs,
            &UploadPolicy {
                enabled: false,
                daily_egress_bytes: 0,
            },
            100,
            1_000,
        )
        .unwrap();
    let session = store
        .active_session(token_hash, "https://capacity.example", 101, true)
        .unwrap()
        .unwrap();
    assert_eq!(session.participant_id, "02".repeat(32));
    assert_eq!(session.last_active_at, 101);
    assert!(!store.persisted_raw_token(raw_token).unwrap());
    assert!(store
        .revoke_session(token_hash, "https://capacity.example", 102)
        .unwrap());
    assert!(store
        .active_session(token_hash, "https://capacity.example", 103, false)
        .unwrap()
        .is_none());
}

#[test]
fn sqlite_rate_limit_is_origin_route_and_minute_bounded() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    assert!(store
        .check_rate_limit("https://a.example", "offers", 60, 2)
        .unwrap());
    assert!(store
        .check_rate_limit("https://a.example", "offers", 61, 2)
        .unwrap());
    assert!(!store
        .check_rate_limit("https://a.example", "offers", 62, 2)
        .unwrap());
    assert!(store
        .check_rate_limit("https://b.example", "offers", 62, 2)
        .unwrap());
    assert!(store
        .check_rate_limit("https://a.example", "offers", 120, 2)
        .unwrap());
}

#[test]
fn preflight_allows_only_declared_noncredentialed_headers() {
    let route = super::mutation_route(
        "/api/wwm-web-capacity/v1/restores/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let request = Request::builder()
        .method(Method::OPTIONS)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization, content-type",
        )
        .body(Body::empty())
        .unwrap();
    super::validate_preflight(&request, route).unwrap();
    let response = super::preflight_response("https://capacity.example", route);
    assert_eq!(response.status(), 204);
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://capacity.example"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "PUT"
    );
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
        "authorization, content-type"
    );
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
        .is_none());

    let rejected = Request::builder()
        .method(Method::OPTIONS)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "cookie")
        .body(Body::empty())
        .unwrap();
    assert!(super::validate_preflight(&rejected, route).is_err());
}

#[test]
fn access_observations_are_coarsened_and_deleted_after_seven_days() {
    assert_eq!(
        super::truncate_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))),
        "203.0.113.0/24"
    );
    assert_eq!(
        super::truncate_ip("2001:db8:1234:5678::1".parse().unwrap()),
        "2001:db8:1234::/48"
    );
    assert_eq!(
        super::coarse_user_agent("Mozilla/5.0 Firefox/128.0"),
        "Firefox"
    );
    assert_eq!(
        super::coarse_user_agent("Mozilla/5.0 Chrome/126.0"),
        "Chromium"
    );
    assert_eq!(
        super::coarse_user_agent("Mozilla/5.0 AppleWebKit/605.1 Safari/605.1"),
        "WebKit"
    );

    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = super::model::ACCESS_LOG_RETENTION_SECONDS + 10;
    store
        .record_access(1, "203.0.113.0/24", "Firefox", "offers", true)
        .unwrap();
    store
        .record_access(now, "2001:db8:1234::/48", "WebKit", "reports", false)
        .unwrap();
    store
        .purge_expired(now, super::model::ACCESS_LOG_RETENTION_SECONDS)
        .unwrap();
    assert_eq!(
        store.access_log_rows().unwrap(),
        vec![(
            now,
            "2001:db8:1234::/48".to_owned(),
            "WebKit".to_owned(),
            "reports".to_owned(),
            false,
        )]
    );
}

#[test]
fn assignments_balance_coordinates_before_adding_second_copies() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0), (0, 1), (0, 2), (0, 3)],
        now + 3_600,
    );
    add_test_session(&store, [0x31; 32], 0x41, now);
    add_test_session(&store, [0x32; 32], 0x42, now);

    let first = store
        .select_assignment_rows([0x31; 32], now, 2, &[])
        .unwrap();
    assert_eq!(coordinates(&first), vec![(0, 0), (0, 1)]);
    store
        .insert_assignment(&"51".repeat(32), [0x31; 32], "{}", now, now + 600, &first)
        .unwrap();

    let second = store
        .select_assignment_rows([0x32; 32], now, 2, &[])
        .unwrap();
    assert_eq!(coordinates(&second), vec![(0, 2), (0, 3)]);
}

#[test]
fn assignments_diversify_provider_cluster_and_region_after_coordinate_balance() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    let host_coordinates = [(0, 0), (0, 1), (0, 2)];
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &host_coordinates,
        now + 3_600,
    );
    add_test_host(
        &store,
        0x12,
        "https://b.example",
        "provider-a",
        "region-b",
        "cluster-b",
        &host_coordinates,
        now + 3_600,
    );
    add_test_host(
        &store,
        0x21,
        "https://c.example",
        "provider-b",
        "region-a",
        "cluster-c",
        &host_coordinates,
        now + 3_600,
    );
    add_test_session(&store, [0x61; 32], 0x71, now);
    add_test_session(&store, [0x62; 32], 0x72, now);

    let first = store
        .select_assignment_rows([0x61; 32], now, 3, &[])
        .unwrap();
    assert_eq!(coordinates(&first), host_coordinates);
    assert_eq!(
        first.iter().map(|(host, _)| host[0]).collect::<Vec<_>>(),
        vec![0x11, 0x21, 0x12]
    );
    assert_eq!(
        first
            .iter()
            .map(|(host, _)| provider_for_host(host))
            .collect::<Vec<_>>(),
        vec!["provider-a", "provider-b", "provider-a"]
    );
    assert_eq!(
        first
            .iter()
            .map(|(host, _)| host[0])
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    store
        .insert_assignment(&"81".repeat(32), [0x61; 32], "{}", now, now + 600, &first)
        .unwrap();

    let second = store
        .select_assignment_rows([0x62; 32], now, 3, &[])
        .unwrap();
    assert_eq!(coordinates(&second), host_coordinates);
    let first_provider = first
        .iter()
        .map(|(host, row)| ((row.stripe, row.position), provider_for_host(host)))
        .collect::<BTreeMap<_, _>>();
    for (host, row) in &second {
        assert_ne!(
            provider_for_host(host),
            first_provider[&(row.stripe, row.position)],
            "coordinate {}:{} repeated a provider despite an alternative",
            row.stripe,
            row.position
        );
    }
}

#[test]
fn removed_or_expired_hosts_stop_future_assignments_without_stale_probe_races() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    let coordinate = [(0, 0)];
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &coordinate,
        now + 600,
    );
    add_test_session(&store, [0x91; 32], 0x92, now);
    let first_generation = store.active_host_refresh_targets().unwrap();
    assert_eq!(first_generation.len(), 1);
    assert_eq!(first_generation[0].generation, 1);

    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &coordinate,
        now + 600,
    );
    assert!(
        !store
            .deactivate_host_if_generation("https://a.example", 1)
            .unwrap(),
        "a stale failed probe deactivated a newer registration"
    );
    let renewed = store.active_host_refresh_targets().unwrap();
    assert_eq!(renewed[0].generation, 2);

    assert!(store
        .deactivate_host_if_generation("https://a.example", 2)
        .unwrap());
    assert!(store
        .select_assignment_rows([0x91; 32], now, 1, &[])
        .unwrap()
        .is_empty());

    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &coordinate,
        now + 1,
    );
    assert_eq!(store.deactivate_expired_hosts(now + 1).unwrap(), 1);
    assert!(store.active_host_refresh_targets().unwrap().is_empty());
}

#[test]
fn concurrent_heartbeats_reserve_diverse_coordinates_atomically() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0), (0, 1), (0, 2), (0, 3)],
        now + 3_600,
    );
    let token_hash = [0x31; 32];
    add_test_session(&store, token_hash, 0x41, now);
    let barrier = Arc::new(Barrier::new(3));
    let workers = [(), ()]
        .into_iter()
        .map(|()| {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store
                    .reserve_assignment(token_hash, now, 2, &[], |rows| {
                        let public_rows =
                            rows.iter().map(|(_, row)| row.clone()).collect::<Vec<_>>();
                        let rows_value = serde_json::to_value(&public_rows).unwrap();
                        let rows_bytes = canonical_json(&rows_value).unwrap();
                        let assignment_id = super::security::domain_hash_hex(
                            noos_crypto::DomainId::WwmWebAssignmentIdV1,
                            &[&token_hash, &now.to_le_bytes(), &rows_bytes],
                        )
                        .unwrap();
                        Ok((
                            assignment_id.clone(),
                            "{}".to_owned(),
                            now + 600,
                            (assignment_id, coordinates(rows)),
                        ))
                    })
                    .unwrap()
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let mut assigned = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assigned.sort_by(|left, right| left.1.cmp(&right.1));
    assert_ne!(assigned[0].0, assigned[1].0);
    assert_eq!(
        assigned
            .iter()
            .map(|(_, rows)| rows.clone())
            .collect::<Vec<_>>(),
        vec![vec![(0, 0), (0, 1)], vec![(0, 2), (0, 3)]]
    );
}

#[test]
fn assignment_respects_available_bytes_and_excludes_held_digests() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0), (0, 1), (0, 2), (0, 3)],
        now + 3_600,
    );
    add_test_session(&store, [0x51; 32], 0x52, now);
    let held = super::security::decode_hex32(&test_protocol_digest(0, 0)).unwrap();
    let available = 3 * super::model::SHARE_BYTES - 1;
    let rows = store
        .reserve_assignment(
            [0x51; 32],
            now,
            (available / super::model::SHARE_BYTES) as usize,
            &[held],
            |rows| {
                Ok((
                    "53".repeat(32),
                    "{}".to_owned(),
                    now + 600,
                    rows.iter().map(|(_, row)| row.clone()).collect::<Vec<_>>(),
                ))
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|row| row.protocol_share_digest != test_protocol_digest(0, 0)));
    assert!(rows.iter().map(|row| row.bytes).sum::<u64>() <= available);
}

#[test]
fn hosts_older_than_sixty_seconds_are_never_assignment_eligible() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0)],
        now + 3_600,
    );
    add_test_session(&store, [0x61; 32], 0x62, now);
    assert!(store
        .select_assignment_rows(
            [0x61; 32],
            now + super::model::HOST_VERIFICATION_MAX_AGE_SECONDS + 2,
            1,
            &[],
        )
        .unwrap()
        .is_empty());
}

#[test]
fn stale_successful_refresh_cannot_replace_a_newer_registration() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open(&temp.path().join("capacity.sqlite")).unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0)],
        now + 3_600,
    );
    let captured = store.active_host_refresh_targets().unwrap()[0].generation;
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-new",
        "region-new",
        "cluster-new",
        &[(0, 1)],
        now + 3_600,
    );
    let (stale_manifest, stale_inventory) =
        test_host_records(0x11, "https://a.example", &[(0, 0)], now + 3_600);
    assert!(!store
        .replace_host_if_generation(
            captured,
            &"11".repeat(32),
            "provider-stale",
            "region-stale",
            "cluster-stale",
            &stale_manifest,
            &stale_inventory,
        )
        .unwrap());
    assert_eq!(
        store.active_host_refresh_targets().unwrap()[0].generation,
        2
    );
    add_test_session(&store, [0x71; 32], 0x72, now);
    assert_eq!(
        coordinates(
            &store
                .select_assignment_rows([0x71; 32], now, 1, &[])
                .unwrap()
        ),
        vec![(0, 1)]
    );
}

#[test]
fn startup_purges_access_observations_without_a_future_request() {
    let temp = tempdir().unwrap();
    let database = temp.path().join("capacity.sqlite");
    {
        let store = WebCapacityStore::open(&database).unwrap();
        store
            .record_access(1, "203.0.113.0/24", "Firefox", "offers", true)
            .unwrap();
    }
    let reopened = WebCapacityStore::open(&database).unwrap();
    assert!(reopened.access_log_rows().unwrap().is_empty());
}

#[test]
fn configured_store_caps_fail_closed_at_each_global_boundary() {
    let temp = tempdir().unwrap();
    let store = WebCapacityStore::open_with_limits(
        &temp.path().join("capacity.sqlite"),
        WebCapacityStoreLimits {
            max_hosts: 1,
            max_active_sessions: 1,
            max_active_assignments: 1,
            max_pending_restore_tasks: 2,
            max_quarantine_bytes: super::model::SHARE_BYTES,
            max_concurrent_restore_verifications: 1,
        },
    )
    .unwrap();
    let now = now_seconds().unwrap();
    add_test_host(
        &store,
        0x11,
        "https://a.example",
        "provider-a",
        "region-a",
        "cluster-a",
        &[(0, 0)],
        now + 3_600,
    );
    let (second_manifest, second_inventory) =
        test_host_records(0x12, "https://b.example", &[(0, 1)], now + 3_600);
    assert!(store
        .replace_host(
            &"12".repeat(32),
            "provider-b",
            "region-b",
            "cluster-b",
            &second_manifest,
            &second_inventory,
        )
        .is_err());

    let token_hash = [0x21; 32];
    store
        .create_session(
            token_hash,
            &"22".repeat(32),
            "https://capacity.example",
            "consent-v1",
            16,
            16 * super::model::SHARE_BYTES,
            StorageClass::Opfs,
            &UploadPolicy {
                enabled: true,
                daily_egress_bytes: 16 * super::model::SHARE_BYTES,
            },
            now,
            now + 3_600,
        )
        .unwrap();
    assert!(store
        .create_session(
            [0x23; 32],
            &"24".repeat(32),
            "https://capacity.example",
            "consent-v1",
            16,
            16 * super::model::SHARE_BYTES,
            StorageClass::Opfs,
            &UploadPolicy {
                enabled: false,
                daily_egress_bytes: 0,
            },
            now,
            now + 3_600,
        )
        .is_err());

    let rows = store
        .select_assignment_rows(token_hash, now, 1, &[])
        .unwrap();
    store
        .insert_assignment(&"31".repeat(32), token_hash, "{}", now, now + 600, &rows)
        .unwrap();
    assert!(store
        .insert_assignment(&"32".repeat(32), token_hash, "{}", now, now + 600, &rows)
        .is_err());

    let (_, inventory) = test_host_records(0x11, "https://a.example", &[(0, 0)], now + 3_600);
    let coordinate = &inventory.rows[0];
    for task_id in ["41".repeat(32), "42".repeat(32)] {
        store
            .queue_restore(
                &task_id,
                token_hash,
                &"22".repeat(32),
                "https://capacity.example",
                coordinate,
                now,
                now + 600,
            )
            .unwrap();
    }
    store
        .begin_restore(
            &"41".repeat(32),
            token_hash,
            "https://capacity.example",
            now,
        )
        .unwrap();
    assert!(store
        .begin_restore(
            &"42".repeat(32),
            token_hash,
            "https://capacity.example",
            now,
        )
        .is_err());
    store
        .fail_restore(&"41".repeat(32), "TEST_RELEASE")
        .unwrap();
    store
        .begin_restore(
            &"42".repeat(32),
            token_hash,
            "https://capacity.example",
            now,
        )
        .unwrap();
    store
        .complete_restore(
            &"42".repeat(32),
            token_hash,
            &"43".repeat(32),
            &"44".repeat(32),
            std::path::Path::new("quarantine.share"),
            now,
            super::model::SHARE_BYTES,
        )
        .unwrap();
    store
        .queue_restore(
            &"45".repeat(32),
            token_hash,
            &"22".repeat(32),
            "https://capacity.example",
            coordinate,
            now,
            now + 600,
        )
        .unwrap();
    assert!(store
        .begin_restore(
            &"45".repeat(32),
            token_hash,
            "https://capacity.example",
            now,
        )
        .is_err());
}

fn coordinates(rows: &[([u8; 32], super::model::AssignmentRow)]) -> Vec<(u32, u8)> {
    rows.iter()
        .map(|(_, row)| (row.stripe, row.position))
        .collect()
}

fn provider_for_host(host: &[u8; 32]) -> &'static str {
    match host[0] {
        0x11 | 0x12 => "provider-a",
        0x21 => "provider-b",
        other => panic!("unexpected test host {other}"),
    }
}

fn add_test_session(store: &WebCapacityStore, token_hash: [u8; 32], participant: u8, now: u64) {
    store
        .create_session(
            token_hash,
            &format!("{participant:02x}").repeat(32),
            "https://capacity.example",
            "consent-v1",
            16,
            16 * super::model::SHARE_BYTES,
            StorageClass::Opfs,
            &UploadPolicy {
                enabled: false,
                daily_egress_bytes: 0,
            },
            now,
            now + 3_600,
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn add_test_host(
    store: &WebCapacityStore,
    host_byte: u8,
    origin: &str,
    provider: &str,
    region: &str,
    control_cluster: &str,
    coordinates: &[(u32, u8)],
    expires_at: u64,
) {
    let (manifest, inventory) = test_host_records(host_byte, origin, coordinates, expires_at);
    store
        .replace_host(
            &format!("{host_byte:02x}").repeat(32),
            provider,
            region,
            control_cluster,
            &manifest,
            &inventory,
        )
        .unwrap();
}

fn test_host_records(
    host_byte: u8,
    origin: &str,
    coordinates: &[(u32, u8)],
    expires_at: u64,
) -> (StaticHostManifest, StaticInventory) {
    let binding = ChainBinding {
        chain_id: "01".repeat(32),
        genesis_hash: "02".repeat(32),
        artifact_id: "03".repeat(32),
        manifest_root: "04".repeat(32),
    };
    let inventory_root = format!("{host_byte:02x}").repeat(32);
    let rows = coordinates
        .iter()
        .map(|(stripe, position)| InventoryRow {
            stripe: *stripe,
            position: *position,
            bytes: super::model::SHARE_BYTES,
            transport_sha256: "05".repeat(32),
            protocol_share_digest: test_protocol_digest(*stripe, *position),
            probe_root: "07".repeat(32),
            url: format!("{origin}/shares/{stripe:06}/{position:02}.share"),
        })
        .collect::<Vec<_>>();
    let inventory = StaticInventory {
        schema: super::model::SCHEMA.to_owned(),
        record_kind: "STATIC_INVENTORY".to_owned(),
        canonical_origin: origin.to_owned(),
        chain_binding: binding.clone(),
        generated_at: expires_at - 600,
        expires_at,
        rows,
        inventory_root: inventory_root.clone(),
    };
    let manifest = StaticHostManifest {
        schema: super::model::SCHEMA.to_owned(),
        record_kind: "STATIC_HOST_MANIFEST".to_owned(),
        participant_class: "STATIC_HOST_SEEDER".to_owned(),
        admission_class: "StatelessReissueable".to_owned(),
        canonical_origin: origin.to_owned(),
        chain_binding: binding,
        host_signing_key: "08".repeat(32),
        valid_from: expires_at - 600,
        expires_at,
        revocation_url: format!("{origin}/.well-known/noos/wwm-web-capacity-v1.json"),
        inventory: InventoryBinding {
            url: format!("{origin}/inventory-v1.json"),
            bytes: 1,
            sha256: "09".repeat(32),
            inventory_root,
        },
        license: LicenseBinding {
            spdx: "Apache-2.0".to_owned(),
            license_url: format!("{origin}/LICENSE.txt"),
            license_sha256: "0a".repeat(32),
            notice_url: format!("{origin}/NOTICE.txt"),
            notice_sha256: "0b".repeat(32),
        },
        transport_policy: TransportPolicy {
            cors_allow_origin: "*".to_owned(),
            credentials: "omit".to_owned(),
            redirects: "reject".to_owned(),
            range_requests: true,
            immutable_cache: true,
            content_encoding: "identity".to_owned(),
        },
        production_custody: false,
        rewards: false,
        signature: Ed25519Signature {
            suite: "Ed25519".to_owned(),
            domain: super::model::HOST_MANIFEST_SIGNATURE_DOMAIN.to_owned(),
            public_key: "08".repeat(32),
            signature: "0c".repeat(64),
        },
    };
    (manifest, inventory)
}

fn test_protocol_digest(stripe: u32, position: u8) -> String {
    let coordinate = stripe
        .saturating_mul(12)
        .saturating_add(u32::from(position));
    format!("{:08x}", coordinate).repeat(8)
}

#[derive(Default)]
struct AdminFirstShareSink {
    first_share: Vec<u8>,
}

impl noos_da::artifact::ArtifactShareSink for AdminFirstShareSink {
    fn stage_share(
        &mut self,
        stripe: u32,
        position: u8,
        bytes: &[u8],
    ) -> std::result::Result<(), noos_da::artifact::ArtifactError> {
        if stripe == 0 && position == 0 {
            self.first_share = bytes.to_vec();
        }
        Ok(())
    }

    fn checkpoint_stripe(
        &mut self,
        _stripe: u32,
    ) -> std::result::Result<(), noos_da::artifact::ArtifactError> {
        Ok(())
    }

    fn checkpoint_artifact_stripe(
        &mut self,
        _stripe: &noos_da::artifact::ArtifactStripeV1,
    ) -> std::result::Result<(), noos_da::artifact::ArtifactError> {
        Ok(())
    }

    fn publish_manifest(
        &mut self,
        _manifest: &noos_da::artifact::ArtifactManifestV1,
    ) -> std::result::Result<(), noos_da::artifact::ArtifactError> {
        Ok(())
    }
}

fn admin_restore_service() -> (
    super::WebCapacityService,
    super::model::QueueRestoreAdminRequest,
    tempfile::TempDir,
) {
    let directory = tempdir().unwrap();
    let mut sink = AdminFirstShareSink::default();
    let canonical_manifest = noos_da::artifact::ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut std::io::Cursor::new(vec![0x5a]), &mut sink, 9)
        .unwrap();
    let commitment = canonical_manifest.stripes[0].shares[0];
    let source_origin = "https://source.example";
    let participant_origin = "https://capacity.example";
    let coordinate = InventoryRow {
        stripe: 0,
        position: 0,
        bytes: super::model::SHARE_BYTES,
        transport_sha256: super::security::sha256_hex(&sink.first_share),
        protocol_share_digest: hex::encode(commitment.share_digest.into_bytes()),
        probe_root: hex::encode(commitment.probe_root.into_bytes()),
        url: format!("{source_origin}/shares/000000/00.share"),
    };
    let now = now_seconds().unwrap();
    let chain_binding = ChainBinding {
        chain_id: "01".repeat(32),
        genesis_hash: "02".repeat(32),
        artifact_id: "03".repeat(32),
        manifest_root: hex::encode(canonical_manifest.manifest_root().into_bytes()),
    };
    let config = super::WebCapacityConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_path: directory.path().join("capacity.sqlite"),
        quarantine_dir: directory.path().join("quarantine"),
        artifact_manifest_path: directory.path().join("unused-manifest.bin"),
        coordinator_seed: [0x31; 32],
        chain_binding: chain_binding.clone(),
        experiment_state: super::model::ExperimentState::LocalFixture,
        source_allowlist: vec![super::SourceRegistration {
            origin: source_origin.to_owned(),
            provider: "provider-a".to_owned(),
            region: "region-a".to_owned(),
            control_cluster: "cluster-a".to_owned(),
        }],
        registered_origins: [participant_origin.to_owned()].into_iter().collect(),
        consent_version: "consent-v1".to_owned(),
        session_lifetime_seconds: 3_600,
        assignment_lifetime_seconds: 300,
        restore_lifetime_seconds: 300,
        host_probe_count: 1,
        request_timeout_ms: 1_000,
        rate_limit_per_minute: 60,
        max_hosts: super::config::HARD_MAX_HOSTS,
        max_active_sessions: super::config::HARD_MAX_ACTIVE_SESSIONS,
        max_active_assignments: super::config::HARD_MAX_ACTIVE_ASSIGNMENTS,
        max_pending_restore_tasks: super::config::HARD_MAX_PENDING_RESTORE_TASKS,
        max_quarantine_bytes: super::config::HARD_MAX_QUARANTINE_BYTES,
        max_concurrent_restore_verifications:
            super::config::HARD_MAX_CONCURRENT_RESTORE_VERIFICATIONS,
        loopback_test_transport: None,
    };
    let store = WebCapacityStore::open(&config.data_path).unwrap();
    let (host_manifest, mut host_inventory) =
        test_host_records(0x51, source_origin, &[(0, 0)], now + 3_600);
    host_inventory.rows[0] = coordinate.clone();
    store
        .replace_host(
            &"51".repeat(32),
            "provider-a",
            "region-a",
            "cluster-a",
            &host_manifest,
            &host_inventory,
        )
        .unwrap();
    let session_token = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [0x41; 32],
    );
    let token_hash = super::session_token_hash(&session_token, participant_origin).unwrap();
    store
        .create_session(
            token_hash,
            &"52".repeat(32),
            participant_origin,
            "consent-v1",
            16,
            16 * super::model::SHARE_BYTES,
            StorageClass::Opfs,
            &UploadPolicy {
                enabled: true,
                daily_egress_bytes: super::model::SHARE_BYTES,
            },
            now,
            now + 3_600,
        )
        .unwrap();
    let canonical_manifest = std::sync::Arc::new(canonical_manifest);
    let host_verifier = super::host::HostVerifier::new(
        std::sync::Arc::new(super::security::ReqwestHostFetcher::new(
            std::time::Duration::from_secs(1),
        )),
        std::sync::Arc::clone(&canonical_manifest),
        chain_binding,
        1,
    );
    let service = super::WebCapacityService {
        inner: std::sync::Arc::new(super::WebCapacityState {
            config,
            store,
            signer: noos_crypto::Keypair::from_seed([0x31; 32]),
            canonical_manifest,
            host_verifier,
        }),
    };
    let request = super::model::QueueRestoreAdminRequest {
        schema: super::model::SCHEMA.to_owned(),
        record_kind: "QUEUE_RESTORE_REQUEST".to_owned(),
        session_token,
        canonical_origin: participant_origin.to_owned(),
        source_origin: source_origin.to_owned(),
        expires_at: now + 120,
        coordinate,
    };
    (service, request, directory)
}

#[test]
fn queue_restore_admin_is_signed_insert_once_and_rejects_invalid_lifecycle_requests() {
    let (service, request, _directory) = admin_restore_service();
    let report = service.queue_restore_admin(request.clone()).unwrap();
    assert_eq!(report.record_kind, "QUEUE_RESTORE_REPORT");
    assert!(report.insert_once);
    assert!(!report.production_custody);
    assert!(!report.rewards);
    assert_eq!(report.task.expires_at, request.expires_at);
    assert_eq!(report.task.coordinate, request.coordinate);
    assert_eq!(
        report.task.signature.domain,
        super::model::RESTORE_TASK_SIGNATURE_DOMAIN
    );
    assert_eq!(report.task.signature.signature.len(), 128);

    assert!(
        service.queue_restore_admin(request.clone()).is_err(),
        "deterministic replay queued a duplicate task"
    );

    let mut unknown = request.clone();
    unknown.session_token = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [0x42; 32],
    );
    assert!(matches!(
        service.queue_restore_admin(unknown),
        Err(super::WebCapacityError::Unauthorized(_))
    ));

    let token_hash =
        super::session_token_hash(&request.session_token, &request.canonical_origin).unwrap();
    service
        .inner
        .store
        .revoke_session(
            token_hash,
            &request.canonical_origin,
            now_seconds().unwrap(),
        )
        .unwrap();
    let mut revoked = request.clone();
    revoked.expires_at = revoked.expires_at.saturating_add(1);
    assert!(matches!(
        service.queue_restore_admin(revoked),
        Err(super::WebCapacityError::Unauthorized(_))
    ));

    let (service, request, _directory) = admin_restore_service();
    let now = now_seconds().unwrap();
    let mut expired = request.clone();
    expired.expires_at = now.saturating_sub(1);
    assert!(service.queue_restore_admin(expired).is_err());
    let mut too_far = request.clone();
    too_far.expires_at = now.saturating_add(301);
    assert!(service.queue_restore_admin(too_far).is_err());

    let mut wrong_participant_origin = request.clone();
    wrong_participant_origin.canonical_origin = "https://other.example".to_owned();
    assert!(service
        .queue_restore_admin(wrong_participant_origin)
        .is_err());
    let mut wrong_source_origin = request.clone();
    wrong_source_origin.source_origin = "https://other.example".to_owned();
    assert!(service.queue_restore_admin(wrong_source_origin).is_err());
    let mut wrong_coordinate_origin = request.clone();
    wrong_coordinate_origin.coordinate.url =
        "https://other.example/shares/000000/00.share".to_owned();
    assert!(service
        .queue_restore_admin(wrong_coordinate_origin)
        .is_err());

    let mut out_of_range = request.clone();
    out_of_range.coordinate.stripe = 1;
    assert!(service.queue_restore_admin(out_of_range).is_err());
    let mut wrong_digest = request;
    wrong_digest.coordinate.protocol_share_digest = "ff".repeat(32);
    assert!(service.queue_restore_admin(wrong_digest).is_err());
}

#[test]
fn restored_position_export_is_signed_complete_and_reverifies_quarantine_bytes() {
    let (service, request, _directory) = admin_restore_service();
    let now = now_seconds().unwrap();
    assert!(service
        .export_restored_position_index(0, now, now + 60)
        .unwrap_err()
        .to_string()
        .contains("requires exactly 1"));

    let queued = service.queue_restore_admin(request.clone()).unwrap();
    let token_hash =
        super::session_token_hash(&request.session_token, &request.canonical_origin).unwrap();
    service
        .inner
        .store
        .begin_restore(
            &queued.task.task_id,
            token_hash,
            &request.canonical_origin,
            now,
        )
        .unwrap();
    let mut sink = AdminFirstShareSink::default();
    noos_da::artifact::ArtifactEncoderV1::new()
        .unwrap()
        .encode(&mut std::io::Cursor::new(vec![0x5a]), &mut sink, 9)
        .unwrap();
    let coordinate_digest = super::security::domain_hash_hex(
        noos_crypto::DomainId::WwmWebCoordinateIdV1,
        &[
            service.inner.config.chain_binding.artifact_id.as_bytes(),
            service.inner.config.chain_binding.manifest_root.as_bytes(),
            &0_u32.to_le_bytes(),
            &[0],
        ],
    )
    .unwrap();
    let quarantine_id = super::security::domain_hash_hex(
        noos_crypto::DomainId::WwmWebQuarantineIdV1,
        &[
            queued.task.task_id.as_bytes(),
            coordinate_digest.as_bytes(),
            request.coordinate.transport_sha256.as_bytes(),
        ],
    )
    .unwrap();
    let path = super::write_quarantine(
        &service.inner.config.quarantine_dir,
        &service.inner.config.chain_binding.artifact_id,
        &quarantine_id,
        &sink.first_share,
    )
    .unwrap();
    service
        .inner
        .store
        .complete_restore(
            &queued.task.task_id,
            token_hash,
            &quarantine_id,
            &coordinate_digest,
            &path,
            now,
            super::model::SHARE_BYTES,
        )
        .unwrap();

    let index = service
        .export_restored_position_index(0, now, now + 60)
        .unwrap();
    assert_eq!(
        index.record_kind,
        super::model::RESTORE_IMPORT_INDEX_RECORD_KIND
    );
    assert_eq!(index.rows.len(), 1);
    assert_eq!(index.rows[0].task, queued.task);
    assert_eq!(
        index.signature.domain,
        super::model::RESTORE_IMPORT_INDEX_SIGNATURE_DOMAIN
    );
    let mut unsigned = serde_json::to_value(&index).unwrap();
    unsigned.as_object_mut().unwrap().remove("signature");
    super::security::verify_json_signature(
        noos_crypto::DomainId::SigWwmWebRestoreImportIndexV1,
        &index.coordinator_public_key,
        &index.signature.signature,
        &unsigned,
    )
    .unwrap();

    let mut tampered = sink.first_share.clone();
    tampered[0] ^= 0x80;
    std::fs::write(&path, tampered).unwrap();
    assert!(service
        .export_restored_position_index(0, now, now + 60)
        .unwrap_err()
        .to_string()
        .contains("transport bytes mismatch"));
    std::fs::write(&path, &sink.first_share).unwrap();

    let canonical_index =
        super::security::canonical_json(&serde_json::to_value(&index).unwrap()).unwrap();
    let manifest = &service.inner.canonical_manifest;
    let evidence = super::model::WebRestoredPositionImportEvidence {
        schema: "noos.wwm.web-restored-position-import-evidence.v1".to_owned(),
        coordinator_public_key: index.coordinator_public_key.clone(),
        chain_id: index.chain_binding.chain_id.clone(),
        genesis_hash: index.chain_binding.genesis_hash.clone(),
        artifact_id: index.chain_binding.artifact_id.clone(),
        manifest_root: index.chain_binding.manifest_root.clone(),
        protocol_payload_root: hex::encode(manifest.protocol_payload_root.as_bytes()),
        published_sha256: hex::encode(manifest.published_sha256),
        position_root: hex::encode(manifest.position_roots[0].as_bytes()),
        import_index_sha256: super::security::sha256_hex(&canonical_index),
        target_position: 0,
        stripe_count: 1,
        imported_share_count: 1,
        imported_bytes: super::model::SHARE_BYTES,
        production_custody: false,
        availability_certificate_effect: false,
        rewards: false,
        insert_once: true,
    };
    let mut forged_evidence = evidence.clone();
    forged_evidence.imported_share_count = 0;
    assert!(service
        .release_restored_position(&index, &forged_evidence, now + 1)
        .is_err());
    assert!(
        path.exists(),
        "failed evidence deleted quarantine before import proof"
    );
    assert_eq!(
        service
            .inner
            .store
            .completed_restores_for_position(0)
            .unwrap()
            .len(),
        1
    );

    let release = service
        .release_restored_position(&index, &evidence, now + 1)
        .unwrap();
    assert_eq!(release.released_share_count, 1);
    assert_eq!(release.released_bytes, super::model::SHARE_BYTES);
    assert!(!release.production_custody);
    assert!(!release.availability_certificate_effect);
    assert!(!release.rewards);
    assert!(!path.exists());
    assert!(service
        .inner
        .store
        .completed_restores_for_position(0)
        .unwrap()
        .is_empty());
    assert!(service
        .release_restored_position(&index, &evidence, now + 2)
        .is_err());
}
