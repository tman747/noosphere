//! MindChain Wallet desktop shell (`noos-wallet-app`).
//!
//! Thin Tauri v2 shell over the `noos-wallet` core: authority derivation,
//! strict Bech32m address validation/display, transaction build + sign, and
//! update-manifest verification. The GUI glue compiles only under the `gui`
//! feature so the core contracts test offline without the webview stack.
#![forbid(unsafe_code)]

pub mod address;
pub mod manifest;
pub mod ops;

#[cfg(feature = "gui")]
mod commands {
    use crate::{address, manifest, ops};

    fn code<E: std::fmt::Display>(e: E) -> String {
        e.to_string()
    }

    #[tauri::command]
    pub fn derive_authority_cmd(req: ops::DeriveRequest) -> Result<ops::DeriveResponse, String> {
        ops::derive(&req).map_err(code)
    }

    #[tauri::command]
    pub fn validate_address_cmd(address: String) -> Result<Vec<u8>, String> {
        address::validate(&address)
            .map(|v| v.payload5)
            .map_err(code)
    }

    #[tauri::command]
    pub fn build_and_sign_cmd(req: ops::SignRequest) -> Result<ops::SignResponse, String> {
        ops::build_and_sign(&req).map_err(code)
    }

    /// Verify an update manifest. The updater key comes from the explicit
    /// argument when present, otherwise from the environment named by the
    /// product-identity policy.
    #[tauri::command]
    pub fn verify_update_manifest_cmd(
        manifest_json: String,
        expected: manifest::ExpectedIdentity,
        runtime: manifest::RuntimeTarget,
        updater_key_hex: Option<String>,
    ) -> Result<(), String> {
        let m: manifest::UpdateManifest = serde_json::from_str(&manifest_json)
            .map_err(|_| manifest::ManifestError::InvalidUpdateManifest.to_string())?;
        let key_hex = match updater_key_hex {
            Some(k) => k,
            None => std::env::var(manifest::UPDATER_PUBLIC_KEY_ENV)
                .map_err(|_| manifest::ManifestError::InvalidUpdaterKey.to_string())?,
        };
        let key = manifest::updater_key_from_hex(&key_hex).map_err(code)?;
        manifest::verify(&m, &expected, &runtime, &key).map_err(code)
    }
}

/// Launch the Tauri shell.
#[cfg(feature = "gui")]
pub fn run() {
    #[allow(clippy::expect_used)] // process entry point: a broken shell must abort loudly
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::derive_authority_cmd,
            commands::validate_address_cmd,
            commands::build_and_sign_cmd,
            commands::verify_update_manifest_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the wallet shell");
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]

    use crate::{address, manifest, ops};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    const DERIVATION_VECTORS: &str =
        include_str!("../../../../protocol/vectors/wallet/derivation-v1.json");
    const API_POSITIVE: &str = include_str!("../../../../protocol/api/vectors/positive.json");
    const API_NEGATIVE: &str = include_str!("../../../../protocol/api/vectors/negative.json");

    fn vector_cases() -> Vec<serde_json::Value> {
        let doc: serde_json::Value = serde_json::from_str(DERIVATION_VECTORS).unwrap();
        doc["cases"].as_array().unwrap().clone()
    }

    #[test]
    fn derivation_matches_frozen_vectors_through_the_command_layer() {
        let cases = vector_cases();
        assert!(cases.len() >= 30, "vector corpus went missing");
        for case in cases {
            assert_eq!(case["kind"], "positive", "unexpected vector kind");
            let req = ops::DeriveRequest {
                seed_hex: case["seed"].as_str().unwrap().to_string(),
                purpose: case["purpose"].as_str().unwrap().to_string(),
                suite: case["suite"].as_u64().map(|s| u32::try_from(s).unwrap()),
                account: u32::try_from(case["account"].as_u64().unwrap()).unwrap(),
                index: u32::try_from(case["index"].as_u64().unwrap()).unwrap(),
            };
            let response = ops::derive(&req).unwrap();
            let expected_path: Vec<String> = case["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect();
            let name = case["name"].as_str().unwrap();
            assert_eq!(response.path, expected_path, "path mismatch for {name}");
            assert_eq!(
                response.bytes,
                case["bytes"].as_str().unwrap(),
                "bytes mismatch for {name}"
            );
            // public_id must equal BLAKE3 of the frozen derived secret: full
            // parity with the vector without exposing the secret on the wire.
            let secret = hex::decode(case["derived_secret"].as_str().unwrap()).unwrap();
            let expected_public = hex::encode(blake3::hash(&secret).as_bytes());
            assert_eq!(
                response.public_id, expected_public,
                "public id mismatch for {name}"
            );
            assert_eq!(
                response.verifying_key.is_some(),
                case["purpose"] == "sign",
                "only the spend purpose may expose a verifying key ({name})"
            );
        }
    }

    #[test]
    fn derivation_rejects_forgeable_requests() {
        let seed = "00".repeat(64);
        let base = ops::DeriveRequest {
            seed_hex: seed.clone(),
            purpose: "sign".into(),
            suite: None,
            account: 0,
            index: 0,
        };
        // Non-hardenable index would alias two different paths.
        for bad in [
            ops::DeriveRequest {
                account: 1 << 31,
                ..base.clone()
            },
            ops::DeriveRequest {
                index: u32::MAX,
                ..base.clone()
            },
            ops::DeriveRequest {
                purpose: "umbra".into(),
                suite: None,
                ..base.clone()
            },
            ops::DeriveRequest {
                purpose: "sign".into(),
                suite: Some(9),
                ..base.clone()
            },
            ops::DeriveRequest {
                purpose: "spend-all".into(),
                ..base.clone()
            },
            ops::DeriveRequest {
                seed_hex: "0G".into(),
                ..base.clone()
            },
        ] {
            assert!(ops::derive(&bad).is_err(), "accepted forgery: {bad:?}");
        }
        // Distinct purposes never collapse to one authority.
        let sign = ops::derive(&base).unwrap();
        let view = ops::derive(&ops::DeriveRequest {
            purpose: "view".into(),
            ..base
        })
        .unwrap();
        assert_ne!(sign.public_id, view.public_id);
        assert!(view.verifying_key.is_none());
    }

    fn api_address_vectors(doc: &str) -> Vec<(String, String, Option<String>)> {
        let doc: serde_json::Value = serde_json::from_str(doc).unwrap();
        doc["vectors"]
            .as_array()
            .or_else(|| doc["cases"].as_array())
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "address")
            .map(|v| {
                (
                    v["id"].as_str().unwrap().to_string(),
                    v["value"].as_str().unwrap().to_string(),
                    v["error"].as_str().map(str::to_string),
                )
            })
            .collect()
    }

    #[test]
    fn address_validation_matches_frozen_api_vectors() {
        let positives = api_address_vectors(API_POSITIVE);
        assert!(!positives.is_empty(), "positive address vector missing");
        for (id, value, _) in positives {
            let verified = address::validate(&value).unwrap_or_else(|e| {
                panic!("canonical vector {id} rejected with {e}");
            });
            // Round-trip: re-encoding the opaque payload reproduces the exact
            // canonical string (checksum included).
            assert_eq!(address::encode(&verified.payload5).unwrap(), value, "{id}");
        }
        let negatives = api_address_vectors(API_NEGATIVE);
        assert!(negatives.len() >= 4, "negative address corpus went missing");
        for (id, value, error) in negatives {
            let expected = error.expect("negative vector must name its error");
            let got = address::validate(&value).expect_err("forged address accepted");
            let code = got.to_string();
            // The two case vectors share one canonical reject class.
            let matches = if expected == "noncanonical_address" {
                code == "noncanonical_address"
            } else {
                code == expected
            };
            assert!(matches, "{id}: expected {expected}, got {code}");
        }
    }

    #[test]
    fn address_rejects_historical_protocol_identity_before_checksum() {
        // Historical HRP assembled from bytes (identity gate): even with a
        // garbage checksum the reject class is wrong_protocol_identity.
        let hist = String::from_utf8(vec![0x6d, 0x69, 0x6e, 0x64]).unwrap();
        let forged = format!("{hist}1qyqqqqgzqvzq2ps");
        assert_eq!(
            address::validate(&forged).unwrap_err().to_string(),
            "wrong_protocol_identity"
        );
        // Encoding never emits anything but the strict noos HRP.
        assert!(address::encode(&[0u8; 32]).unwrap().starts_with("noos1"));
    }

    #[test]
    fn address_length_and_charset_bounds_hold() {
        assert_eq!(
            address::validate("noos1qqqqq").unwrap_err().to_string(),
            "bad_length"
        );
        // 'b' is outside the Bech32 charset.
        assert_eq!(
            address::validate("noos1bqqqqqq").unwrap_err().to_string(),
            "bad_charset"
        );
        assert_eq!(
            address::encode(&[32u8]).unwrap_err().to_string(),
            "bad_charset"
        );
        assert_eq!(
            address::encode(&[0u8; 84]).unwrap_err().to_string(),
            "bad_length"
        );
    }

    fn updater_key() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn signed_manifest(signing: &SigningKey) -> manifest::UpdateManifest {
        let mut m = manifest::UpdateManifest {
            app_id: manifest::APP_ID.into(),
            chain_id: "a".repeat(64),
            genesis_hash: "b".repeat(64),
            platform: "windows".into(),
            arch: "x86_64".into(),
            version: "1.2.3".into(),
            channel: "stable".into(),
            artifact_sha256: "d".repeat(64),
            signature: String::new(),
        };
        m.signature = hex::encode(signing.sign(&manifest::signing_bytes(&m)).to_bytes());
        m
    }

    fn policy() -> (manifest::ExpectedIdentity, manifest::RuntimeTarget) {
        (
            manifest::ExpectedIdentity {
                chain_id: "a".repeat(64),
                genesis_hash: "b".repeat(64),
            },
            manifest::RuntimeTarget {
                platform: "windows".into(),
                arch: "x86_64".into(),
                channel: "stable".into(),
            },
        )
    }

    #[test]
    fn update_manifest_accepts_only_the_signed_exact_target() {
        let (signing, verifying) = updater_key();
        let (expected, runtime) = policy();
        let m = signed_manifest(&signing);
        manifest::verify(&m, &expected, &runtime, &verifying).unwrap();
    }

    #[test]
    fn update_manifest_falsifiers_reject_every_forgery_class() {
        let (signing, verifying) = updater_key();
        let (expected, runtime) = policy();
        let good = signed_manifest(&signing);

        // Tampered artifact hash: structure remains valid, signature must die.
        let mut tampered = good.clone();
        tampered.artifact_sha256 = "e".repeat(64);
        assert_eq!(
            manifest::verify(&tampered, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "bad_signature"
        );

        // Version rollback swap: same fields resigned by an ATTACKER key.
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let mut resigned = good.clone();
        resigned.version = "0.0.1".into();
        resigned.signature = hex::encode(
            attacker
                .sign(&manifest::signing_bytes(&resigned))
                .to_bytes(),
        );
        assert_eq!(
            manifest::verify(&resigned, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "bad_signature"
        );

        // Wrong chain identity binds before targets.
        let mut wrong_chain = good.clone();
        wrong_chain.chain_id = "c".repeat(64);
        assert_eq!(
            manifest::verify(&wrong_chain, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "wrong_protocol_identity"
        );

        // Wrong app id.
        let mut wrong_app = good.clone();
        wrong_app.app_id = "network.example.other".into();
        assert_eq!(
            manifest::verify(&wrong_app, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "wrong_protocol_identity"
        );

        // Cross-target replay: signed manifest for another arch/platform/channel.
        for (field, value) in [
            ("arch", "aarch64"),
            ("platform", "linux"),
            ("channel", "beta"),
        ] {
            let mut cross = good.clone();
            match field {
                "arch" => cross.arch = value.into(),
                "platform" => cross.platform = value.into(),
                _ => cross.channel = value.into(),
            }
            cross.signature =
                hex::encode(signing.sign(&manifest::signing_bytes(&cross)).to_bytes());
            assert_eq!(
                manifest::verify(&cross, &expected, &runtime, &verifying)
                    .unwrap_err()
                    .to_string(),
                "wrong_update_target",
                "cross-target replay via {field}"
            );
        }

        // Unknown channel even when it matches nothing at runtime.
        let mut nightly = good.clone();
        nightly.channel = "nightly".into();
        assert_eq!(
            manifest::verify(&nightly, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "wrong_update_target"
        );

        // Structural forgeries.
        let mut upper = good.clone();
        upper.artifact_sha256 = "D".repeat(64);
        assert_eq!(
            manifest::verify(&upper, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "invalid_update_manifest"
        );
        let mut short_sig = good.clone();
        short_sig.signature = "aa".into();
        assert_eq!(
            manifest::verify(&short_sig, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "invalid_update_manifest"
        );
        let mut empty = good;
        empty.version = String::new();
        assert_eq!(
            manifest::verify(&empty, &expected, &runtime, &verifying)
                .unwrap_err()
                .to_string(),
            "invalid_update_manifest"
        );

        // Key policy: malformed updater keys never verify anything.
        assert!(manifest::updater_key_from_hex("zz").is_err());
        assert!(manifest::updater_key_from_hex(&"A".repeat(64)).is_err());
    }

    fn identity(api_version: u16) -> ops::IdentityHex {
        ops::IdentityHex {
            chain_id: "a".repeat(64),
            genesis_hash: "b".repeat(64),
            api_version,
        }
    }

    fn sign_request() -> ops::SignRequest {
        let unit = ops::ResourcesReq {
            bytes: "1".into(),
            grain_steps: "1".into(),
            proof_units: "0".into(),
            state_reads: "0".into(),
            state_writes: "0".into(),
            blob_bytes: "0".into(),
        };
        ops::SignRequest {
            seed_hex: "42".repeat(64),
            account: 0,
            index: 0,
            expected: identity(1),
            actual: identity(1),
            notes: vec![
                ops::NoteReq {
                    id: "11".repeat(32),
                    amount: "600".into(),
                },
                ops::NoteReq {
                    id: "22".repeat(32),
                    amount: "500".into(),
                },
            ],
            amount: "700".into(),
            resources: ops::ResourcesReq {
                bytes: "100".into(),
                grain_steps: "10".into(),
                ..unit.clone()
            },
            prices: unit,
        }
    }

    #[test]
    fn transaction_build_and_sign_produces_a_verifiable_submission() {
        let req = sign_request();
        let res = ops::build_and_sign(&req).unwrap();
        // fee = 100*1 + 10*1 = 110; needs 810 -> both notes; change 290.
        assert_eq!(res.fee, "110");
        assert_eq!(res.change, "290");
        assert_eq!(res.inputs.len(), 2);
        // Independent verification: rebuild the exact signed message.
        let vk_bytes: [u8; 32] = hex::decode(&res.verifying_key).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let sig_bytes: [u8; 64] = hex::decode(&res.signature).unwrap().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let body = hex::decode(&res.body).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(noos_wallet::SIGNING_DOMAIN);
        msg.extend_from_slice(&[0xaa; 32]);
        msg.extend_from_slice(&[0xbb; 32]);
        msg.extend_from_slice(&1u16.to_le_bytes());
        msg.extend_from_slice(&body);
        vk.verify_strict(&msg, &sig).unwrap();
        // Falsifier: one flipped body byte must not verify.
        let mut forged = msg.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(vk.verify_strict(&forged, &sig).is_err());
        // Determinism: same request, same txid.
        assert_eq!(ops::build_and_sign(&req).unwrap().txid, res.txid);
    }

    #[test]
    fn transaction_signing_fails_closed_on_identity_and_funds() {
        // Wrong chain identity: the gate refuses before any signing.
        let mut wrong_chain = sign_request();
        wrong_chain.actual.chain_id = "c".repeat(64);
        assert_eq!(
            ops::build_and_sign(&wrong_chain).unwrap_err().to_string(),
            "wrong_protocol_identity"
        );
        // API version skew.
        let mut skew = sign_request();
        skew.actual.api_version = 2;
        assert_eq!(
            ops::build_and_sign(&skew).unwrap_err().to_string(),
            "api_version_mismatch"
        );
        // Insufficient funds for amount + fee.
        let mut poor = sign_request();
        poor.amount = "100000".into();
        assert_eq!(
            ops::build_and_sign(&poor).unwrap_err().to_string(),
            "insufficient funds"
        );
        // Non-canonical amount encodings are rejected, not coerced.
        for bad in ["", "0700", "7.5", "-1", "1e3"] {
            let mut malformed = sign_request();
            malformed.amount = bad.into();
            assert_eq!(
                ops::build_and_sign(&malformed).unwrap_err().to_string(),
                "invalid_request",
                "accepted malformed amount {bad:?}"
            );
        }
    }
}
