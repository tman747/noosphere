from __future__ import annotations

import copy
import datetime as dt
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import production_authorization as pa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


REVISION = "1" * 40


class AuthorizationFixtures:
    def setUp(self) -> None:
        roles = list(pa.CUTOVER_ROLES) + ["independent-genesis-rebuilder"] + [f"dkg-participant:p{i}" for i in range(1, 4)]
        roles = list(dict.fromkeys(roles))
        self.private: dict[str, Ed25519PrivateKey] = {}
        self.keyring: dict[str, pa.RoleKey] = {}
        for index, role in enumerate(roles, 1):
            private = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
            public_hex = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ).hex()
            self.private[role] = private
            self.keyring[role] = pa.RoleKey(role, f"test-key-{index}", private.public_key(), public_hex)

        self.params = {
            "schema_version": 1,
            "chain_name": "noos-mainnet-owner-selected",
            "is_test_network": False,
            "is_template": False,
            "owner_signed": True,
            "token": {"symbol": "NOOS", "decimals": 6, "base_unit": "micro-NOOS"},
            "consensus": {
                "slot_seconds": 6, "epoch_length": 256, "max_slot_skip": 20,
                "median_time_past_blocks": 11, "witness_membership_lookback_epochs": 2,
                "pulse_target_spacing_seconds": 6, "pulse_half_life_seconds": 3600,
                "max_future_drift_ms": 18_000,
            },
            "witness_ring": {"n_max": 256, "n_tail": 32, "n_hard": 1024, "min_bond_micro_noos": 123},
            "controls": dict(pa.ZERO_CONTROLS),
            "emission": {
                "max_supply_micro_noos": 1_000_000,
                "emission_terminal_height": 10_000,
                "emission_table_root": "2" * 64,
                "recipient_share_ground_bp": 5000,
                "recipient_share_witness_bp": 3000,
                "recipient_share_treasury_bp": 2000,
                "rounding_rule_id": 1,
                "fee_disposition_id": 1,
            },
            "allocations": {"allocations_root": "3" * 64},
            "commitments": {
                "claim_registry_root": "4" * 64,
                "conformance_vector_root": "5" * 64,
                "software_manifest_root": "6" * 64,
            },
            "dkg": {"participants": 3, "threshold": 2},
            "authorization": {
                "exact_revision": REVISION,
                "role_keyring_path": "owner/keyring.json",
                "signed_repro_policy_record_path": "owner/repro.signatures.json",
            },
            "signatures": {"record_path": "owner/freeze.signatures.json", "required_roles": list(pa.FREEZE_ROLES)},
        }
        canonical = pa.canonical_mainnet_manifest(self.params, test_mode=True)
        manifest_hash = pa.domain_hash(b"NOOS/GENESIS/PARAMS/V1", canonical).hex()
        self.freeze = {
            "schema_version": 1,
            "kind": "noosphere-canonical-parameter-freeze-v1",
            "exact_revision": REVISION,
            "canonical_manifest_bytes_hex": canonical.hex(),
            "parameter_manifest_hash": manifest_hash,
            "chain_id": pa.domain_hash(b"NOOS/CHAIN/V1", bytes.fromhex(manifest_hash)).hex(),
            "is_test_fixture": True,
        }
        self.freeze_signatures = self.sign(self.freeze, pa.DOMAIN_FREEZE, pa.FREEZE_ROLES)

    def sign(self, payload, domain, roles):
        raw = pa.canonical_json(payload)
        entries = []
        for role in roles:
            key = self.keyring[role]
            entries.append({
                "role": role,
                "key_id": key.key_id,
                "signature_ed25519_hex": self.private[role].sign(pa.signature_message(domain, raw)).hex(),
            })
        return {
            "schema_version": 1,
            "kind": "noosphere-detached-role-signatures-v1",
            "algorithm": "ed25519",
            "domain": domain,
            "payload_sha256": pa.sha256(raw),
            "exact_revision": REVISION,
            "required_roles": list(roles),
            "role_label_notice": "Signatures authorize bytes for named roles; they do not prove that a signer is an independent human.",
            "signatures": entries,
        }

    def descriptor(self):
        participants = [
            {"participant_id": f"p{i}", "index": i, "signing_role": f"dkg-participant:p{i}"}
            for i in range(1, 4)
        ]
        freeze_hash = pa.sha256(pa.canonical_json(self.freeze) + b"\n")
        publication_hash = "2" * 64
        authorized_at = "2030-01-08T00:00:00Z"
        ceremony_id = pa.domain_hash(
            b"NOOS/DKG/CEREMONY-ID/V1",
            bytes.fromhex(self.freeze["chain_id"]),
            pa.canonical_json({
                "freeze_manifest_sha256": freeze_hash,
                "quiet_week_publication_sha256": publication_hash,
                "authorized_at_utc": authorized_at,
                "threshold": 2,
                "participants": participants,
            }),
        ).hex()
        descriptor = {
            "schema_version": 1,
            "kind": "noosphere-dealerless-dkg-v1",
            "ceremony_id": ceremony_id,
            "exact_revision": REVISION,
            "freeze_manifest_sha256": freeze_hash,
            "quiet_week_publication_sha256": publication_hash,
            "authorized_at_utc": authorized_at,
            "chain_id": self.freeze["chain_id"],
            "threshold": 2,
            "participants": participants,
            "is_test_fixture": True,
            "assurance_limit": "test fixture",
        }
        return descriptor, self.sign(descriptor, pa.DOMAIN_DKG_DESCRIPTOR, pa.FREEZE_ROLES)

    def dkg_material(self, bad_dealers=()):
        descriptor, descriptor_signatures = self.descriptor()
        contributions = []
        states = {}
        for i in range(1, 4):
            role_name = f"dkg-participant:p{i}"
            contribution, state = pa.dkg_contribution(
                descriptor, f"p{i}", self.keyring[role_name], self.private[role_name],
                coefficients=[10 + i, 20 + i], test_mode=True,
            )
            contributions.append(contribution); states[f"p{i}"] = state
        reviews = []
        self.last_packets = {f"p{i}": [] for i in range(1, 4)}
        for dealer_index, contribution in enumerate(contributions, 1):
            dealer_id = f"p{dealer_index}"
            for recipient_index in range(1, 4):
                recipient_id = f"p{recipient_index}"
                dealer_role = self.keyring[f"dkg-participant:{dealer_id}"]
                packet = pa.dkg_share_packet(
                    states[dealer_id], descriptor, recipient_id, dealer_role,
                    self.private[dealer_role.role],
                )
                if dealer_id in bad_dealers and recipient_index == 1:
                    payload = dict(packet["payload"])
                    payload["share_scalar_hex"] = f"{int(payload['share_scalar_hex'], 16) + 1:064x}"
                    packet = pa._signed_record(payload, dealer_role, self.private[dealer_role.role])
                self.last_packets[recipient_id].append(packet)
                recipient_role = self.keyring[f"dkg-participant:{recipient_id}"]
                reviews.append(pa.dkg_review_record(
                    packet, contribution, recipient_role, self.private[recipient_role.role], self.keyring
                ))
        erasures = []
        for i, contribution in enumerate(contributions, 1):
            role = self.keyring[f"dkg-participant:p{i}"]
            erasures.append(pa.dkg_erasure_record(
                descriptor, contribution, f"p{i}", role, self.private[role.role],
                dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc), test_mode=True,
            ))
        exclusions = []
        for dealer in bad_dealers:
            complaint_hashes = sorted(
                pa.sha256(pa.canonical_json(r["payload"]))
                for r in reviews
                if r["payload"]["dealer_id"] == dealer and r["payload"]["verdict"] == "COMPLAINT"
            )
            exclusions.append({"dealer_id": dealer, "complaint_hashes": complaint_hashes})
        exclusions.sort(key=lambda e: int(e["dealer_id"][1:]))
        return descriptor, descriptor_signatures, contributions, reviews, exclusions, erasures

    @staticmethod
    def mine_header(previous_internal: bytes, timestamp: int, nonce_seed: int = 0):
        bits = 0x207FFFFF
        for nonce in range(nonce_seed, nonce_seed + 100_000):
            raw = (
                (4).to_bytes(4, "little") + previous_internal + bytes([9]) * 32
                + timestamp.to_bytes(4, "little") + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little")
            )
            fields = pa.header_fields(raw.hex())
            if int.from_bytes(fields["hash_internal"], "little") <= fields["target"]:
                return raw.hex(), fields
        raise AssertionError("test header mining did not converge")


class ParameterAndSignatureTests(AuthorizationFixtures, unittest.TestCase):
    def test_canonical_manifest_and_signature_positive(self):
        pa.verify_freeze_manifest(self.freeze, self.freeze_signatures, self.keyring, test_mode=True)
        self.assertGreater(len(bytes.fromhex(self.freeze["canonical_manifest_bytes_hex"])), 300)

    def test_placeholder_economics_refused(self):
        bad = copy.deepcopy(self.params)
        bad["emission"]["max_supply_micro_noos"] = "OWNER_BLOCKED"
        with self.assertRaisesRegex(pa.AuthorizationError, "placeholder"):
            pa.canonical_mainnet_manifest(bad)

    def test_zero_economics_and_test_fixture_refused(self):
        bad = copy.deepcopy(self.params); bad["emission"]["max_supply_micro_noos"] = 0
        with self.assertRaisesRegex(pa.AuthorizationError, "placeholder zero economics"):
            pa.canonical_mainnet_manifest(bad)
        fixture = copy.deepcopy(self.params); fixture["dkg"]["is_test_fixture"] = True
        with self.assertRaisesRegex(pa.AuthorizationError, "test fixture"):
            pa.canonical_mainnet_manifest(fixture)
        devnet_bond = copy.deepcopy(self.params)
        devnet_bond["witness_ring"]["min_bond_micro_noos"] = 1_000_000_000_000
        with self.assertRaisesRegex(pa.AuthorizationError, "devnet bond fixture"):
            pa.canonical_mainnet_manifest(devnet_bond)

    def test_stale_revision_missing_role_invalid_signature_and_hash_mismatch(self):
        stale = copy.deepcopy(self.freeze_signatures); stale["exact_revision"] = "2" * 40
        with self.assertRaisesRegex(pa.AuthorizationError, "stale revision"):
            pa.verify_freeze_manifest(self.freeze, stale, self.keyring, test_mode=True)
        missing = copy.deepcopy(self.freeze_signatures); missing["signatures"].pop()
        with self.assertRaisesRegex(pa.AuthorizationError, "missing/extra role"):
            pa.verify_freeze_manifest(self.freeze, missing, self.keyring, test_mode=True)
        invalid = copy.deepcopy(self.freeze_signatures)
        invalid["signatures"][0]["signature_ed25519_hex"] = "00" * 64
        with self.assertRaisesRegex(pa.AuthorizationError, "invalid signature"):
            pa.verify_freeze_manifest(self.freeze, invalid, self.keyring, test_mode=True)
        mismatch = copy.deepcopy(self.freeze); mismatch["parameter_manifest_hash"] = "0" * 64
        with self.assertRaisesRegex(pa.AuthorizationError, "parameter manifest hash mismatch"):
            pa.verify_freeze_manifest(mismatch, self.freeze_signatures, self.keyring, test_mode=True)


class QuietWeekAndBitcoinTests(AuthorizationFixtures, unittest.TestCase):
    def test_quiet_week_uses_elapsed_test_clock_and_live_bytes(self):
        published = pa.canonical_json(self.freeze) + b"\n"
        first = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        record = pa.make_publication_record(
            self.freeze, "test://fixture", published, first, test_mode=True
        )
        signatures = self.sign(record, pa.DOMAIN_PUBLICATION, pa.FREEZE_ROLES)
        elapsed = pa.verify_quiet_week(
            record, signatures, self.freeze, self.keyring, published,
            now=first + dt.timedelta(seconds=pa.QUIET_WEEK_SECONDS), test_mode=True,
        )
        self.assertEqual(elapsed, pa.QUIET_WEEK_SECONDS)
        with self.assertRaisesRegex(pa.AuthorizationError, "has not elapsed"):
            pa.verify_quiet_week(
                record, signatures, self.freeze, self.keyring, published,
                now=first + dt.timedelta(days=6), test_mode=True,
            )

    def test_bitcoin_pow_chain_and_pre_quiet_anchor_falsifier(self):
        first = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
        publication = {"exact_revision": REVISION, "first_observed_at_utc": pa.utc_text(first)}
        after = int((first + dt.timedelta(days=8)).timestamp())
        checkpoint_hex, checkpoint = self.mine_header(bytes(32), after)
        anchor_hex, anchor = self.mine_header(checkpoint["hash_internal"], after + 600)
        bundle = {
            "schema_version": 1, "kind": "noosphere-bitcoin-anchor-chain-v1",
            "exact_revision": REVISION, "is_test_fixture": True,
            "trusted_checkpoint": {"height": 100, "header_hex": checkpoint_hex, "block_hash_display_hex": checkpoint["hash_display"]},
            "headers": [{"height": 101, "header_hex": anchor_hex}],
            "anchor_height": 101, "anchor_hash_display_hex": anchor["hash_display"],
            "minimum_chainwork_hex": "1", "anchor_observed_at_utc": pa.utc_text(first + dt.timedelta(days=8)),
        }
        summary = pa.verify_bitcoin_anchor_bundle(bundle, publication, test_mode=True)
        self.assertEqual(summary["block_hash_display_hex"], anchor["hash_display"])
        signatures = self.sign(bundle, pa.DOMAIN_BITCOIN_ANCHOR, pa.FREEZE_ROLES)
        pa.verify_signed_bitcoin_anchor(bundle, signatures, self.keyring, REVISION)
        pre_hex, pre = self.mine_header(checkpoint["hash_internal"], int((first + dt.timedelta(days=6)).timestamp()))
        bad = copy.deepcopy(bundle)
        bad["headers"] = [{"height": 101, "header_hex": pre_hex}]
        bad["anchor_hash_display_hex"] = pre["hash_display"]
        with self.assertRaisesRegex(pa.AuthorizationError, "pre-quiet-week"):
            pa.verify_bitcoin_anchor_bundle(bad, publication, test_mode=True)


class DkgTests(AuthorizationFixtures, unittest.TestCase):
    def valid_transcript(self):
        material = self.dkg_material()
        return pa.finalize_dkg_transcript(*material, self.keyring, self.freeze, test_mode=True)

    def test_dealerless_transcript_positive(self):
        transcript = self.valid_transcript()
        summary = pa.verify_dkg_transcript(transcript, self.keyring, self.freeze, test_mode=True)
        self.assertEqual(summary["active_participants"], ["p1", "p2", "p3"])
        self.assertEqual(summary["threshold"], 2)
        role = self.keyring["dkg-participant:p1"]
        public, secret = pa.dkg_finalize_participant_share(
            transcript, self.last_packets["p1"], "p1", self.keyring, self.freeze,
            role, self.private[role.role], test_mode=True,
        )
        self.assertEqual(public["payload"]["participant_id"], "p1")
        self.assertEqual(len(secret["secret_share_scalar_hex"]), 64)

    def test_threshold_failure(self):
        material = self.dkg_material(bad_dealers=("p1", "p2"))
        with self.assertRaisesRegex(pa.AuthorizationError, "threshold failure"):
            pa.finalize_dkg_transcript(*material, self.keyring, self.freeze, test_mode=True)

    def test_rogue_contribution_transcript_splice_complaint_omission_and_reordering(self):
        transcript = self.valid_transcript()
        rogue = copy.deepcopy(transcript)
        payload = dict(rogue["contributions"][0]["payload"]); payload["dealer_id"] = "rogue"
        role = self.keyring["dkg-participant:p1"]
        rogue["contributions"][0] = pa._signed_record(payload, role, self.private[role.role])
        with self.assertRaisesRegex(pa.AuthorizationError, "rogue"):
            pa.verify_dkg_transcript(rogue, self.keyring, self.freeze, test_mode=True)

        splice = copy.deepcopy(transcript)
        payload = dict(splice["reviews"][0]["payload"]); payload["ceremony_id"] = "0" * 64
        role = self.keyring["dkg-participant:p1"]
        splice["reviews"][0] = pa._signed_record(payload, role, self.private[role.role])
        with self.assertRaisesRegex(pa.AuthorizationError, "transcript splice"):
            pa.verify_dkg_transcript(splice, self.keyring, self.freeze, test_mode=True)

        omission = copy.deepcopy(transcript); omission["reviews"].pop()
        with self.assertRaisesRegex(pa.AuthorizationError, "omission"):
            pa.verify_dkg_transcript(omission, self.keyring, self.freeze, test_mode=True)

        reordered = copy.deepcopy(transcript); reordered["contributions"][0], reordered["contributions"][1] = reordered["contributions"][1], reordered["contributions"][0]
        with self.assertRaisesRegex(pa.AuthorizationError, "order"):
            pa.verify_dkg_transcript(reordered, self.keyring, self.freeze, test_mode=True)


class CutoverTests(AuthorizationFixtures, unittest.TestCase):
    def cutover_fixture(self):
        promotion = {
            "protocol_binding": {"revision": REVISION},
            "cutover": {"execution_authority": "SIGNED_G5_ONLY"},
            "gates": [
                {"gate": name, "state": "PASSED", "signatures": [{"fixture": True}]}
                for name in ("G0", "G1", "G2", "G3", "GENESIS", "G4", "G5")
            ],
        }
        final = {"exact_revision": REVISION, "chain_id": self.freeze["chain_id"], "genesis_hash": "7" * 64}
        release = {"identity": {"chain_id": final["chain_id"], "genesis_hash": final["genesis_hash"]}, "source": {"repo_revision": REVISION}}
        prepared = {
            "manifest_state": "PREPARED_NOT_EXECUTED",
            "execution": {
                "authorized": False, "executed": False, "dns_cutover": "PROHIBITED",
                "required_authority": "SIGNED_G5_PROMOTION_OVER_EXACT_MANIFEST_HASH",
            },
        }
        authorization = {
            "schema_version": 1,
            "kind": "noosphere-multiparty-cutover-authorization-v1",
            "exact_revision": REVISION,
            "chain_id": final["chain_id"],
            "genesis_hash": final["genesis_hash"],
            "promotion_ledger_sha256": pa.sha256(pa.canonical_json(promotion) + b"\n"),
            "release_manifest_sha256": pa.sha256(pa.canonical_json(release) + b"\n"),
            "final_freeze_sha256": pa.sha256(pa.canonical_json(final) + b"\n"),
            "prepared_cutover_sha256": pa.sha256(pa.canonical_json(prepared) + b"\n"),
            "is_test_fixture": False,
            "authorization_scope": "exact bytes only",
        }
        signatures = self.sign(authorization, pa.DOMAIN_CUTOVER, pa.CUTOVER_ROLES)
        return authorization, signatures, promotion, release, final, prepared

    def test_cutover_multiparty_positive_and_hash_mismatch(self):
        values = self.cutover_fixture()
        pa.verify_cutover_authorization(values[0], values[1], self.keyring, *values[2:])
        bad = copy.deepcopy(values[0]); bad["release_manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(pa.AuthorizationError, "component hash mismatch"):
            pa.verify_cutover_authorization(bad, values[1], self.keyring, *values[2:])

    def test_current_blocked_gate_and_missing_cutover_role_refuse(self):
        authorization, signatures, promotion, release, final, prepared = self.cutover_fixture()
        promotion["gates"][4]["state"] = "BLOCKED"
        with self.assertRaisesRegex(pa.AuthorizationError, "every G0..G5"):
            pa.verify_cutover_authorization(authorization, signatures, self.keyring, promotion, release, final, prepared)
        promotion["gates"][4]["state"] = "PASSED"
        signatures["signatures"].pop()
        with self.assertRaisesRegex(pa.AuthorizationError, "missing/extra role"):
            pa.verify_cutover_authorization(authorization, signatures, self.keyring, promotion, release, final, prepared)


class FinalGenesisTests(AuthorizationFixtures, unittest.TestCase):
    def test_final_genesis_rebuild_is_deterministic_and_binds_every_root(self):
        material = self.dkg_material()
        transcript = pa.finalize_dkg_transcript(*material, self.keyring, self.freeze, test_mode=True)
        dkg = pa.verify_dkg_transcript(transcript, self.keyring, self.freeze, test_mode=True)
        anchor = {"height": 900_000, "block_hash_internal_hex": "8" * 64}
        body = {
            "version": 1,
            "parameter_manifest_hash": self.freeze["parameter_manifest_hash"],
            "genesis_time_ms": 1_900_000_000_000,
            "dkg_suite_id": 1,
            "dkg_group_pubkey_hex": dkg["group_public_key_g1_hex"],
            "dkg_participant_set_root": dkg["participant_set_root"],
            "genesis_witness_set_root": "9" * 64,
            "genesis_state_roots": {
                "notes_root": "a" * 64,
                "nullifiers_root": "b" * 64,
                "accounts_root": "c" * 64,
                "objects_root": "d" * 64,
                "receipts_root": "e" * 64,
                "params_root": "f" * 64,
            },
            "is_test_fixture": True,
        }
        first = pa.derive_final_identity(self.freeze, anchor, dkg, body, test_mode=True)
        second = pa.derive_final_identity(self.freeze, anchor, dkg, body, test_mode=True)
        self.assertEqual(first, second)
        mutated = copy.deepcopy(body); mutated["genesis_state_roots"]["accounts_root"] = "0" * 64
        changed = pa.derive_final_identity(self.freeze, anchor, dkg, mutated, test_mode=True)
        self.assertNotEqual(first["genesis_hash"], changed["genesis_hash"])


if __name__ == "__main__":
    unittest.main()
