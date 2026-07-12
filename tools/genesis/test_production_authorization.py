from __future__ import annotations

import copy
import datetime as dt
import sys
import tempfile
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
        roles = list(pa.CUTOVER_ROLES) + ["independent-genesis-rebuilder"] + [f"dkg-participant:p{i}" for i in range(1, 8)]
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

    def descriptor(self, participant_count=3, threshold=2):
        participants = [
            {"participant_id": f"p{i}", "index": i, "signing_role": f"dkg-participant:p{i}"}
            for i in range(1, participant_count + 1)
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
                "threshold": threshold,
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
            "threshold": threshold,
            "participants": participants,
            "is_test_fixture": True,
            "assurance_limit": "test fixture",
        }
        return descriptor, self.sign(descriptor, pa.DOMAIN_DKG_DESCRIPTOR, pa.FREEZE_ROLES)

    def dkg_material(self, bad_dealers=(), participant_count=3, threshold=2):
        descriptor, descriptor_signatures = self.descriptor(participant_count, threshold)
        contributions = []
        states = {}
        for i in range(1, participant_count + 1):
            role_name = f"dkg-participant:p{i}"
            contribution, state = pa.dkg_contribution(
                descriptor, f"p{i}", self.keyring[role_name], self.private[role_name],
                coefficients=[10 * degree + i for degree in range(1, threshold + 1)], test_mode=True,
            )
            contributions.append(contribution); states[f"p{i}"] = state
        reviews = []
        self.last_packets = {f"p{i}": [] for i in range(1, participant_count + 1)}
        for dealer_index, contribution in enumerate(contributions, 1):
            dealer_id = f"p{dealer_index}"
            for recipient_index in range(1, participant_count + 1):
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
                    packet, contribution, descriptor, recipient_role,
                    self.private[recipient_role.role], self.keyring
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

    def dkg_core(self, material):
        return pa.build_dkg_core_transcript(
            *material, self.keyring, self.freeze, test_mode=True,
        )

    def possession_records(self, core, holders):
        active = set(pa.verify_dkg_core_transcript(
            core, self.keyring, self.freeze, test_mode=True,
        )["active_participants"])
        records = []
        for participant_id in holders:
            role = self.keyring[f"dkg-participant:{participant_id}"]
            packets = [
                packet for packet in self.last_packets[participant_id]
                if packet["payload"]["dealer_id"] in active
            ]
            public, _ = pa.dkg_finalize_participant_share(
                core, packets, participant_id, self.keyring, self.freeze,
                role, self.private[role.role], test_mode=True,
            )
            records.append(public)
        return records

    def finalized_dkg(self, material, holders=None):
        core = self.dkg_core(material)
        if holders is None:
            holders = [p["participant_id"] for p in core["descriptor"]["participants"]][:core["descriptor"]["threshold"]]
        records = self.possession_records(core, holders)
        return pa.finalize_dkg_core_transcript(
            core, records, self.keyring, self.freeze, test_mode=True,
        )

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
        return self.finalized_dkg(material)

    def test_dealerless_transcript_positive(self):
        transcript = self.valid_transcript()
        summary = pa.verify_dkg_transcript(transcript, self.keyring, self.freeze, test_mode=True)
        self.assertEqual(summary["active_participants"], ["p1", "p2", "p3"])
        self.assertEqual(summary["threshold"], 2)
        self.assertEqual(summary["verified_share_holders"], ["p1", "p2"])
        self.assertEqual(transcript["schema_version"], 2)
        self.assertEqual(transcript["core"]["schema_version"], 2)

    def test_threshold_failure(self):
        material = self.dkg_material(bad_dealers=("p1", "p2"))
        with self.assertRaisesRegex(pa.AuthorizationError, "threshold failure"):
            pa.finalize_dkg_transcript(*material, self.keyring, self.freeze, test_mode=True)

    def test_share_packet_is_bound_to_descriptor_dealer_recipient_and_context(self):
        descriptor, _, contributions, _, _, _ = self.dkg_material()
        packet = self.last_packets["p2"][0]
        self.assertTrue(pa.verify_share_against_contribution(
            packet, contributions[0], descriptor, "p2", self.keyring
        ))

        participant_b = self.keyring["dkg-participant:p3"]
        wrong_signer = pa._signed_record(
            packet["payload"], participant_b, self.private[participant_b.role]
        )
        with self.assertRaisesRegex(
            pa.AuthorizationError, "packet signer does not match descriptor dealer"
        ):
            pa.verify_share_against_contribution(
                wrong_signer, contributions[0], descriptor, "p2", self.keyring
            )

        dealer = self.keyring["dkg-participant:p1"]
        wrong_recipient_payload = dict(packet["payload"])
        wrong_recipient_payload["recipient_id"] = "p3"
        wrong_recipient = pa._signed_record(
            wrong_recipient_payload, dealer, self.private[dealer.role]
        )
        with self.assertRaisesRegex(
            pa.AuthorizationError, "recipient does not match expected recipient"
        ):
            pa.verify_share_against_contribution(
                wrong_recipient, contributions[0], descriptor, "p2", self.keyring
            )

        spliced_contribution_payload = dict(contributions[0]["payload"])
        spliced_contribution_payload["ceremony_id"] = "0" * 64
        spliced_contribution = pa._signed_record(
            spliced_contribution_payload, dealer, self.private[dealer.role]
        )
        spliced_packet_payload = dict(packet["payload"])
        spliced_packet_payload["ceremony_id"] = "0" * 64
        spliced_packet_payload["public_contribution_sha256"] = pa.sha256(
            pa.canonical_json(spliced_contribution_payload)
        )
        spliced_packet = pa._signed_record(
            spliced_packet_payload, dealer, self.private[dealer.role]
        )
        with self.assertRaisesRegex(
            pa.AuthorizationError, "descriptor context mismatch at ceremony_id"
        ):
            pa.verify_share_against_contribution(
                spliced_packet, spliced_contribution, descriptor, "p2", self.keyring
            )

    def test_forged_packet_cannot_create_complaint_or_exclude_honest_dealer(self):
        descriptor, signatures, contributions, reviews, _, erasures = self.dkg_material()
        honest_packet = self.last_packets["p2"][0]
        forged_payload = dict(honest_packet["payload"])
        forged_payload["share_scalar_hex"] = (
            f"{int(forged_payload['share_scalar_hex'], 16) + 1:064x}"
        )
        participant_b = self.keyring["dkg-participant:p3"]
        forged_packet = pa._signed_record(
            forged_payload, participant_b, self.private[participant_b.role]
        )
        recipient = self.keyring["dkg-participant:p2"]
        with self.assertRaisesRegex(
            pa.AuthorizationError, "packet signer does not match descriptor dealer"
        ):
            pa.dkg_review_record(
                forged_packet, contributions[0], descriptor, recipient,
                self.private[recipient.role], self.keyring,
            )

        complaint_payload = dict(reviews[1]["payload"])
        complaint_payload["packet_sha256"] = pa.sha256(pa.canonical_json(forged_packet))
        complaint_payload["verdict"] = "COMPLAINT"
        complaint_payload["complaint_packet"] = forged_packet
        forged_reviews = copy.deepcopy(reviews)
        forged_reviews[1] = pa._signed_record(
            complaint_payload, recipient, self.private[recipient.role]
        )
        exclusions = [{
            "dealer_id": "p1",
            "complaint_hashes": [pa.sha256(pa.canonical_json(complaint_payload))],
        }]
        with self.assertRaisesRegex(
            pa.AuthorizationError, "packet signer does not match descriptor dealer"
        ):
            pa.finalize_dkg_transcript(
                descriptor, signatures, contributions, forged_reviews, exclusions, erasures,
                self.keyring, self.freeze, test_mode=True,
            )

        dealer = self.keyring["dkg-participant:p1"]
        other_recipient_payload = dict(self.last_packets["p3"][0]["payload"])
        other_recipient_payload["share_scalar_hex"] = (
            f"{int(other_recipient_payload['share_scalar_hex'], 16) + 1:064x}"
        )
        other_recipient_packet = pa._signed_record(
            other_recipient_payload, dealer, self.private[dealer.role]
        )
        recipient_splice_payload = dict(reviews[1]["payload"])
        recipient_splice_payload["packet_sha256"] = pa.sha256(
            pa.canonical_json(other_recipient_packet)
        )
        recipient_splice_payload["verdict"] = "COMPLAINT"
        recipient_splice_payload["complaint_packet"] = other_recipient_packet
        recipient_splice_reviews = copy.deepcopy(reviews)
        recipient_splice_reviews[1] = pa._signed_record(
            recipient_splice_payload, recipient, self.private[recipient.role]
        )
        recipient_splice_exclusions = [{
            "dealer_id": "p1",
            "complaint_hashes": [pa.sha256(pa.canonical_json(recipient_splice_payload))],
        }]
        with self.assertRaisesRegex(
            pa.AuthorizationError, "recipient does not match expected recipient"
        ):
            pa.finalize_dkg_transcript(
                descriptor, signatures, contributions, recipient_splice_reviews,
                recipient_splice_exclusions, erasures, self.keyring, self.freeze,
                test_mode=True,
            )

    def test_invalid_dealer_signed_share_remains_a_valid_complaint(self):
        material = self.dkg_material(bad_dealers=("p1",))
        transcript = self.finalized_dkg(material, ["p2", "p3"])
        summary = pa.verify_dkg_transcript(
            transcript, self.keyring, self.freeze, test_mode=True
        )
        self.assertEqual(summary["excluded_participants"], ["p1"])
        self.assertEqual(summary["active_participants"], ["p2", "p3"])

    def test_rogue_contribution_transcript_splice_complaint_omission_and_reordering(self):
        transcript = self.valid_transcript()
        rogue = copy.deepcopy(transcript)
        payload = dict(rogue["core"]["contributions"][0]["payload"]); payload["dealer_id"] = "rogue"
        role = self.keyring["dkg-participant:p1"]
        rogue["core"]["contributions"][0] = pa._signed_record(payload, role, self.private[role.role])
        with self.assertRaisesRegex(pa.AuthorizationError, "rogue"):
            pa.verify_dkg_transcript(rogue, self.keyring, self.freeze, test_mode=True)

        splice = copy.deepcopy(transcript)
        payload = dict(splice["core"]["reviews"][0]["payload"]); payload["ceremony_id"] = "0" * 64
        role = self.keyring["dkg-participant:p1"]
        splice["core"]["reviews"][0] = pa._signed_record(payload, role, self.private[role.role])
        with self.assertRaisesRegex(pa.AuthorizationError, "transcript splice"):
            pa.verify_dkg_transcript(splice, self.keyring, self.freeze, test_mode=True)

        omission = copy.deepcopy(transcript); omission["core"]["reviews"].pop()
        with self.assertRaisesRegex(pa.AuthorizationError, "omission"):
            pa.verify_dkg_transcript(omission, self.keyring, self.freeze, test_mode=True)

        reordered = copy.deepcopy(transcript); reordered["core"]["contributions"][0], reordered["core"]["contributions"][1] = reordered["core"]["contributions"][1], reordered["core"]["contributions"][0]
        with self.assertRaisesRegex(pa.AuthorizationError, "order"):
            pa.verify_dkg_transcript(reordered, self.keyring, self.freeze, test_mode=True)

    def test_valid_reviews_without_threshold_possession_remain_incomplete(self):
        material = list(self.dkg_material())
        fabricated = []
        for review in material[3]:
            payload = dict(review["payload"])
            payload["packet_sha256"] = "0" * 64
            role = self.keyring[f"dkg-participant:{payload['recipient_id']}"]
            fabricated.append(pa._signed_record(payload, role, self.private[role.role]))
        material[3] = fabricated
        core = self.dkg_core(tuple(material))
        with self.assertRaisesRegex(pa.AuthorizationError, "fewer than threshold"):
            pa.finalize_dkg_core_transcript(core, [], self.keyring, self.freeze, test_mode=True)

    def test_final_share_holder_identity_context_and_possession_falsifiers(self):
        material = self.dkg_material()
        core = self.dkg_core(material)
        shares = self.possession_records(core, ["p1", "p2", "p3"])
        with self.assertRaisesRegex(pa.AuthorizationError, "fewer than threshold"):
            pa.finalize_dkg_core_transcript(core, shares[:1], self.keyring, self.freeze, test_mode=True)
        with self.assertRaisesRegex(pa.AuthorizationError, "duplicate"):
            pa.finalize_dkg_core_transcript(core, [shares[0], shares[0]], self.keyring, self.freeze, test_mode=True)

        def resigned(index, **changes):
            payload = dict(shares[index]["payload"]); payload.update(changes)
            role = self.keyring[f"dkg-participant:{payload['participant_id']}"]
            return pa._signed_record(payload, role, self.private[role.role])

        wrong_role = pa._signed_record(
            shares[0]["payload"], self.keyring["dkg-participant:p3"], self.private["dkg-participant:p3"],
        )
        for bad, pattern in (
            ([wrong_role, shares[1]], "exact participant role"),
            ([resigned(0, participant_index=2), shares[1]], "index mismatch"),
            ([resigned(0, core_root="0" * 64), shares[1]], "core_root"),
            ([resigned(0, possession_proof_g2_compressed_hex="00" * 96), shares[1]], "proof of possession invalid"),
            ([resigned(0, public_share_g1_compressed_hex=shares[1]["payload"]["public_share_g1_compressed_hex"]), shares[1]], "public share mismatch"),
        ):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(pa.AuthorizationError, pattern):
                pa.finalize_dkg_core_transcript(core, bad, self.keyring, self.freeze, test_mode=True)

    def test_excluded_holder_rejected_and_valid_five_of_seven_possession(self):
        excluded_material = self.dkg_material(bad_dealers=("p1",))
        excluded_core = self.dkg_core(excluded_material)
        active_shares = self.possession_records(excluded_core, ["p2", "p3"])
        payload = dict(active_shares[0]["payload"])
        payload.update(participant_id="p1", participant_index=1)
        role = self.keyring["dkg-participant:p1"]
        excluded_holder = pa._signed_record(payload, role, self.private[role.role])
        with self.assertRaisesRegex(pa.AuthorizationError, "rogue or excluded"):
            pa.finalize_dkg_core_transcript(
                excluded_core, [excluded_holder, active_shares[1]], self.keyring, self.freeze, test_mode=True,
            )

        material = self.dkg_material(participant_count=7, threshold=5)
        transcript = self.finalized_dkg(material, ["p1", "p2", "p3", "p4", "p5"])
        summary = pa.verify_dkg_transcript(transcript, self.keyring, self.freeze, test_mode=True)
        self.assertEqual(summary["verified_share_holders"], ["p1", "p2", "p3", "p4", "p5"])
        self.assertEqual(summary["threshold"], 5)


class CutoverTests(AuthorizationFixtures, unittest.TestCase):
    def cutover_fixture(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        trust_root = "a" * 64
        final = {
            "exact_revision": REVISION, "chain_id": self.freeze["chain_id"],
            "genesis_hash": "7" * 64, "role_keyring_sha256": trust_root,
        }
        final_hash = pa.sha256(pa.canonical_json(final) + b"\n")
        requirement_ids = {
            "G0": ["G0.REGISTRY_SCHEMA", "G0.OWNER_CONSTANTS"],
            "G1": ["G1.DETERMINISTIC_LAB"], "G2": ["G2.INDEPENDENT_DEVNET"],
            "G3": ["G3.PUBLIC_DURATION", "G3.A_BRAID_AI_OFF", "G3.EXTERNAL_ASSURANCE"],
            "GENESIS": ["GENESIS.QUIET_WEEK", "GENESIS.BITCOIN_ANCHOR", "GENESIS.DKG", "GENESIS.MAINNET_ECONOMICS", "GENESIS.REPRO_DEMO"],
            "G4": ["G4.CANARY_DURATION", "G4.EXIT_AND_FAULT_DRILLS", "G4.HARDWARE_BUILDERS"],
            "G5": ["G5.EXACT_LOWER_GATES", "G5.CLAIM_COMPLETENESS", "G5.EXTERNAL_REVIEWS", "G5.LIVE_DIVERSITY", "G5.SIGNATURES"],
        }
        record_hashes = []
        gates = []
        for gate_id, ids in requirement_ids.items():
            evidence_doc = {
                "schema": "noos/test-promotion-evidence/v1", "kind": "signed-test-fixture",
                "gate_id": gate_id, "exact_revision": REVISION, "chain_id": final["chain_id"],
                "genesis_hash": final["genesis_hash"], "is_test_fixture": True, "verdict": "PASS",
            }
            evidence_path = root / f"{gate_id.lower()}.json"
            evidence_path.write_bytes(pa.canonical_json(evidence_doc))
            evidence_hash = pa.file_sha256(evidence_path)
            record = {
                "schema_version": 2, "kind": "noosphere-promotion-gate-record-v2", "gate_id": gate_id,
                "exact_revision": REVISION, "chain_id": final["chain_id"], "genesis_hash": final["genesis_hash"],
                "ordered_prerequisite_record_hashes": list(record_hashes), "requirement_ids": ids,
                "evidence_artifacts": [{
                    "requirement_id": requirement_id, "path": evidence_path.name, "sha256": evidence_hash,
                    "schema": "noos/test-promotion-evidence/v1", "kind": "signed-test-fixture",
                } for requirement_id in ids],
                "unresolved": [], "decision": "PASSED", "signer_roles": list(pa.CUTOVER_ROLES),
                "signer_key_ids": [self.keyring[role].key_id for role in pa.CUTOVER_ROLES],
                "predecessor_record_hash": record_hashes[-1] if record_hashes else "0" * 64,
                "predecessor_ledger_root": pa.sha256(b"NOOS/PROMOTION/LEDGER/V2\x00" + pa.canonical_json(record_hashes)),
                "role_keyring_sha256": trust_root,
            }
            raw = pa.canonical_json(record)
            signatures = [{
                "role": role, "key_id": self.keyring[role].key_id,
                "signature_ed25519_hex": self.private[role].sign(b"NOOS/PROMOTION/GATE/V2\x00" + raw).hex(),
            } for role in pa.CUTOVER_ROLES]
            record_hashes.append(pa.sha256(raw))
            gates.append({
                "gate": gate_id, "state": "PASSED", "requirements": [{
                    "requirement_id": requirement_id, "status": "SATISFIED", "verdict": "PASS",
                    "exact_revision": REVISION,
                } for requirement_id in ids], "unresolved": [],
                "authorization_record": record, "signatures": signatures,
            })
        ledger_root = pa.sha256(b"NOOS/PROMOTION/LEDGER/V2\x00" + pa.canonical_json(record_hashes))
        promotion = {
            "protocol_binding": {"revision": REVISION, "chain_id": final["chain_id"], "genesis_hash": final["genesis_hash"]},
            "authorization_binding": {
                "schema_version": 2, "gate_record_domain": "NOOS/PROMOTION/GATE/V2",
                "role_keyring_sha256": trust_root, "final_freeze_sha256": final_hash, "ledger_root": ledger_root,
            },
            "cutover": {"execution_authority": "SIGNED_G5_ONLY"}, "gates": gates,
        }
        release = {"identity": {"chain_id": final["chain_id"], "genesis_hash": final["genesis_hash"]}, "source": {"repo_revision": REVISION}}
        prepared = {
            "manifest_state": "PREPARED_NOT_EXECUTED",
            "execution": {
                "authorized": False, "executed": False, "dns_cutover": "PROHIBITED",
                "required_authority": "SIGNED_G5_PROMOTION_OVER_EXACT_MANIFEST_HASH",
            },
        }
        authorization = {
            "schema_version": 2,
            "kind": "noosphere-multiparty-cutover-authorization-v2",
            "exact_revision": REVISION,
            "chain_id": final["chain_id"],
            "genesis_hash": final["genesis_hash"],
            "promotion_ledger_sha256": pa.sha256(pa.canonical_json(promotion) + b"\n"),
            "promotion_ledger_root": ledger_root,
            "role_keyring_sha256": trust_root,
            "release_manifest_sha256": pa.sha256(pa.canonical_json(release) + b"\n"),
            "final_freeze_sha256": pa.sha256(pa.canonical_json(final) + b"\n"),
            "prepared_cutover_sha256": pa.sha256(pa.canonical_json(prepared) + b"\n"),
            "is_test_fixture": True,
            "authorization_scope": "exact bytes only",
        }
        signatures = self.sign(authorization, pa.DOMAIN_CUTOVER, pa.CUTOVER_ROLES)
        return authorization, signatures, promotion, release, final, prepared, trust_root, root

    def test_cutover_multiparty_positive_and_hash_mismatch(self):
        values = self.cutover_fixture()
        pa.verify_cutover_authorization(
            values[0], values[1], self.keyring, *values[2:6],
            trusted_role_keyring_sha256=values[6], promotion_root=values[7], test_mode=True,
        )
        bad = copy.deepcopy(values[0]); bad["release_manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(pa.AuthorizationError, "component hash mismatch"):
            pa.verify_cutover_authorization(
                bad, values[1], self.keyring, *values[2:6],
                trusted_role_keyring_sha256=values[6], promotion_root=values[7], test_mode=True,
            )

    def test_current_blocked_gate_and_missing_cutover_role_refuse(self):
        authorization, signatures, promotion, release, final, prepared, trust_root, root = self.cutover_fixture()
        promotion["gates"][4]["state"] = "BLOCKED"
        with self.assertRaisesRegex(pa.AuthorizationError, "non-PASSED gate"):
            pa.verify_cutover_authorization(
                authorization, signatures, self.keyring, promotion, release, final, prepared,
                trusted_role_keyring_sha256=trust_root, promotion_root=root, test_mode=True,
            )
        promotion["gates"][4]["state"] = "PASSED"
        signatures["signatures"].pop()
        with self.assertRaisesRegex(pa.AuthorizationError, "missing/extra role"):
            pa.verify_cutover_authorization(
                authorization, signatures, self.keyring, promotion, release, final, prepared,
                trusted_role_keyring_sha256=trust_root, promotion_root=root, test_mode=True,
            )

    def test_passed_strings_and_dummy_signature_objects_never_authorize(self):
        authorization, _, _, release, final, prepared, trust_root, root = self.cutover_fixture()
        fabricated = {
            "protocol_binding": {"revision": REVISION, "chain_id": final["chain_id"], "genesis_hash": final["genesis_hash"]},
            "authorization_binding": {
                "schema_version": 2, "gate_record_domain": "NOOS/PROMOTION/GATE/V2",
                "role_keyring_sha256": trust_root,
                "final_freeze_sha256": pa.sha256(pa.canonical_json(final) + b"\n"),
                "ledger_root": authorization["promotion_ledger_root"],
            },
            "cutover": {"execution_authority": "SIGNED_G5_ONLY"},
            "gates": [{"gate": gate, "state": "PASSED", "signatures": [{"fixture": True}]} for gate in ("G0", "G1", "G2", "G3", "GENESIS", "G4", "G5")],
        }
        authorization = dict(authorization)
        authorization["promotion_ledger_sha256"] = pa.sha256(pa.canonical_json(fabricated) + b"\n")
        signatures = self.sign(authorization, pa.DOMAIN_CUTOVER, pa.CUTOVER_ROLES)
        with self.assertRaisesRegex(pa.AuthorizationError, "authorization record"):
            pa.verify_cutover_authorization(
                authorization, signatures, self.keyring, fabricated, release, final, prepared,
                trusted_role_keyring_sha256=trust_root, promotion_root=root, test_mode=True,
            )

    def test_signed_gate_file_existence_without_exact_evidence_bytes_fails(self):
        authorization, signatures, promotion, release, final, prepared, trust_root, root = self.cutover_fixture()
        (root / "g3.json").write_text('{"schema":"noos/test-promotion-evidence/v1"}', encoding="utf-8")
        with self.assertRaisesRegex(pa.AuthorizationError, "evidence bytes/hash mismatch"):
            pa.verify_cutover_authorization(
                authorization, signatures, self.keyring, promotion, release, final, prepared,
                trusted_role_keyring_sha256=trust_root, promotion_root=root, test_mode=True,
            )


class FinalGenesisTests(AuthorizationFixtures, unittest.TestCase):
    def test_final_genesis_rebuild_is_deterministic_and_binds_every_root(self):
        material = self.dkg_material()
        transcript = self.finalized_dkg(material)
        dkg = pa.verify_dkg_transcript(transcript, self.keyring, self.freeze, test_mode=True)
        anchor = {"height": 900_000, "block_hash_internal_hex": "8" * 64}
        body = {
            "version": 2,
            "parameter_manifest_hash": self.freeze["parameter_manifest_hash"],
            "genesis_time_ms": 1_900_000_000_000,
            "dkg_suite_id": 1,
            "dkg_group_pubkey_hex": dkg["group_public_key_g1_hex"],
            "dkg_participant_set_root": dkg["participant_set_root"],
            "dkg_holder_set_root": dkg["holder_set_root"],
            "dkg_root": dkg["dkg_root"],
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
