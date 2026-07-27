from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping

from tools.operations import wwm_hosted_model_demo as demo

SCHEMA = "noos/wwm-public-inference-settlement-request/v1"
RESULT_SCHEMA = "noos/wwm-public-inference-settlement-result/v1"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
ENVELOPE_DOMAIN = b"NOOS/WWM/PUBLIC-INFERENCE/CHAIN-ENVELOPE/V1\0"


class PublicSettlementError(RuntimeError):
    pass


def _object(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, dict):
        raise PublicSettlementError(f"{key} must be an object")
    return selected


def _text(value: Mapping[str, Any], key: str, *, hex32: bool = False) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise PublicSettlementError(f"{key} must be non-empty text")
    if hex32 and HEX32.fullmatch(selected) is None:
        raise PublicSettlementError(f"{key} must be canonical hex32")
    return selected


def _uint(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if isinstance(selected, bool) or not isinstance(selected, int) or selected < 0:
        raise PublicSettlementError(f"{key} must be an unsigned integer")
    return selected


def _missing_record(error: demo.DemoError) -> bool:
    return "HTTP 404" in str(error)


class DevnetSettlementBackend:
    """Resumable testnet-only WWM job, receipt, and settlement publisher."""

    def __init__(self, *, hosted_config: Path, node_rpc: str, node_token: str):
        try:
            self.hosted = demo.load_object(hosted_config.resolve(strict=True))
            self.paths, configured_network = demo.validate_contract(self.hosted)
        except (OSError, demo.DemoError) as error:
            raise PublicSettlementError("hosted-model settlement configuration is invalid") from error
        if not self.paths.cli.is_file():
            raise PublicSettlementError("typed WWM settlement CLI is unavailable")
        self.network = replace(
            configured_network,
            node_rpc=node_rpc.rstrip("/"),
            node_token=node_token,
        )

    @staticmethod
    def capture(snapshot: object) -> dict[str, Any]:
        resolution = getattr(snapshot, "resolution", None)
        if not isinstance(resolution, dict):
            raise PublicSettlementError("finalized resolution is unavailable for settlement")
        active = _object(resolution, "active")
        executors = active.get("executor_profile_ids")
        if (
            not isinstance(executors, list)
            or len(executors) < 3
            or not all(isinstance(value, str) and HEX32.fullmatch(value) for value in executors)
        ):
            raise PublicSettlementError("finalized resolution lacks three canonical executors")
        binding = {
            "chain_id": _text(resolution, "chain_id", hex32=True),
            "genesis_hash": _text(resolution, "genesis_hash", hex32=True),
            "resolution_finalized_height": _uint(resolution, "finalized_height"),
            "resolution_finalized_hash": _text(resolution, "finalized_hash", hex32=True),
            "capsule_id": _text(active, "capsule_id", hex32=True),
            "artifact_id": _text(active, "artifact_id", hex32=True),
            "tokenizer_root": _text(active, "tokenizer_root", hex32=True),
            "template_root": _text(active, "template_root", hex32=True),
            "runtime_root": _text(active, "runtime_root", hex32=True),
            "sbom_root": _text(active, "sbom_root", hex32=True),
            "execution_profile_id": _text(active, "execution_profile_id", hex32=True),
            "query_policy_id": _text(active, "query_policy_id", hex32=True),
            "availability_certificate_id": _text(active, "availability_certificate_id", hex32=True),
            "fund_profile_id": _text(active, "fund_profile_id", hex32=True),
            "certificate_valid_until": _uint(active, "certificate_valid_until"),
            "executor_set_epoch": _uint(active, "executor_set_epoch"),
            "executor_ids": list(executors[:3]),
        }
        return binding

    def _prepare_plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        binding = _object(request, "binding")
        quote = _object(request, "quote")
        status = demo.http_json(f"{self.network.node_rpc}/status", self.network.node_token)
        chain_id = demo.required_text(status, "chain_id")
        genesis_hash = demo.required_text(status, "genesis_hash")
        if chain_id != _text(binding, "chain_id") or genesis_hash != _text(binding, "genesis_hash"):
            raise PublicSettlementError("settlement node belongs to another chain")
        head_height = demo.required_int(demo.required_object(status, "unsafe_head"), "height")
        job_id = _text(request, "job_id", hex32=True)
        prompt_commitment = _text(quote, "prompt_commitment", hex32=True)
        executor_ids = binding.get("executor_ids")
        if not isinstance(executor_ids, list) or len(executor_ids) != 3:
            raise PublicSettlementError("settlement binding lacks the bounded executor set")
        bindings = {
            "capsule_id": _text(binding, "capsule_id", hex32=True),
            "artifact_id": _text(binding, "artifact_id", hex32=True),
            "tokenizer_root": _text(binding, "tokenizer_root", hex32=True),
            "template_root": _text(binding, "template_root", hex32=True),
            "runtime_root": _text(binding, "runtime_root", hex32=True),
            "sbom_root": _text(binding, "sbom_root", hex32=True),
            "execution_profile_id": _text(binding, "execution_profile_id", hex32=True),
            "query_policy_id": _text(binding, "query_policy_id", hex32=True),
            "availability_certificate_id": _text(binding, "availability_certificate_id", hex32=True),
            "fund_profile_id": _text(binding, "fund_profile_id", hex32=True),
            "certificate_valid_until": _uint(binding, "certificate_valid_until"),
        }
        envelope_root = hashlib.sha256(
            ENVELOPE_DOMAIN
            + bytes.fromhex(job_id)
            + bytes.fromhex(_text(quote, "quote_id", hex32=True))
            + bytes.fromhex(prompt_commitment)
        ).hexdigest()
        job = {
            "job_id": job_id,
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "quote_id": _text(quote, "quote_id", hex32=True),
            "registry_epoch": _uint(binding, "executor_set_epoch"),
            "client_commitment": prompt_commitment,
            "capsule_id": bindings["capsule_id"],
            "execution_profile_id": bindings["execution_profile_id"],
            "query_policy_id": bindings["query_policy_id"],
            "max_input_tokens": _uint(quote, "input_tokens"),
            "max_output_tokens": _uint(quote, "maximum_output_tokens"),
            "deadline_height": head_height + 5_000,
            "selected_executor_ids": list(executor_ids),
            "availability_certificate_id": bindings["availability_certificate_id"],
            "fund_profile_id": bindings["fund_profile_id"],
            "reserved_amount": "0",
            "offchain_envelope_root": envelope_root,
        }
        return {
            "schema": "noos/wwm-chain-bound-inference-plan/v1",
            "run_id": job_id[:24],
            "job_id": job_id,
            "receipt_id": _text(request, "receipt_id", hex32=True),
            "settlement_id": _text(request, "settlement_id", hex32=True),
            "prompt_commitment": prompt_commitment,
            "executor_ids": list(executor_ids),
            "bindings": bindings,
            "job": job,
        }

    @staticmethod
    def _prepare_close(
        request: Mapping[str, Any],
        plan: Mapping[str, Any],
        job_record: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = _object(request, "binding")
        quote = _object(request, "quote")
        inference = _object(request, "inference")
        executor_ids = plan.get("executor_ids")
        if not isinstance(executor_ids, list) or len(executor_ids) != 3:
            raise PublicSettlementError("settlement plan lacks the bounded executor set")
        job_id = _text(request, "job_id", hex32=True)
        receipt_id = _text(request, "receipt_id", hex32=True)
        settlement_id = _text(request, "settlement_id", hex32=True)
        terminal_status = request.get("terminal_status")
        error_code = request.get("error_code")
        if terminal_status == "COMPLETED":
            terminal_code = "complete"
        elif terminal_status == "CANCELLED":
            terminal_code = "cancelled"
        elif terminal_status == "FAILED":
            terminal_code = (
                "deadline" if error_code == "JOB_DEADLINE_EXPIRED" else "rejected"
            )
        elif terminal_status == "NO_QUORUM":
            terminal_code = "no_quorum"
        else:
            raise PublicSettlementError("settlement terminal status is invalid")
        output_tokens = _uint(inference, "output_tokens")
        token_history_root = _text(inference, "token_history_root", hex32=True)
        output_root = _text(inference, "output_root", hex32=True)
        completed = terminal_code == "complete"
        if completed and (
            output_tokens == 0
            or token_history_root == "0" * 64
            or output_root == "0" * 64
        ):
            raise PublicSettlementError("completed settlement lacks output commitments")
        if not completed and (
            output_tokens != 0
            or token_history_root != "0" * 64
            or output_root != "0" * 64
        ):
            raise PublicSettlementError("refunded settlement contains output commitments")
        anchor_height = _uint(job_record, "finalized_height")
        signer_ids = list(executor_ids) if completed else []
        evidence_tier = "no_quorum" if terminal_code == "no_quorum" else "local_verified"
        receipt = {
            "receipt_id": receipt_id,
            "job_id": job_id,
            "capsule_id": _text(binding, "capsule_id", hex32=True),
            "artifact_id": _text(binding, "artifact_id", hex32=True),
            "tokenizer_root": _text(binding, "tokenizer_root", hex32=True),
            "template_root": _text(binding, "template_root", hex32=True),
            "runtime_root": _text(binding, "runtime_root", hex32=True),
            "sbom_root": _text(binding, "sbom_root", hex32=True),
            "execution_profile_id": _text(binding, "execution_profile_id", hex32=True),
            "input_tokens": _uint(quote, "input_tokens"),
            "output_tokens": output_tokens,
            "token_history_root": token_history_root,
            "output_root": output_root,
            "signer_ids": signer_ids,
            "control_cluster_ids": signer_ids,
            "evidence_tier": evidence_tier,
            "availability_until": _uint(binding, "certificate_valid_until"),
            "evidence_until": _uint(binding, "certificate_valid_until"),
            "anchor_height": anchor_height,
            "anchor_block": _text(job_record, "finalized_hash", hex32=True),
            "metered_amount": "0",
            "paid_amount": "0",
            "refunded_amount": "0",
            "terminal_code": terminal_code,
            "signatures": [],
        }
        settlement = {
            "settlement_id": settlement_id,
            "job_id": job_id,
            "receipt_id": receipt_id,
            "fund_profile_id": _text(binding, "fund_profile_id", hex32=True),
            "bucket": "job",
            "prior_settlement_index": 0,
            "paid_amount": "0",
            "refunded_amount": "0",
            "released_amount": "0",
            "settled_height": anchor_height,
            "authority_epoch": 1,
            "signature": demo.MARKER_SIGNATURE_HEX,
        }
        return {
            "schema": "noos/wwm-chain-bound-close-plan/v1",
            "receipt": receipt,
            "settlement": settlement,
        }

    @staticmethod
    def _checkpoint(
        current: Mapping[str, Any],
        callback: Callable[[dict[str, Any]], None],
        phase: str,
        **updates: Any,
    ) -> dict[str, Any]:
        next_value = {**current, **updates, "phase": phase}
        callback(next_value)
        return next_value

    def settle(
        self,
        request: Mapping[str, Any],
        checkpoint: Mapping[str, Any],
        on_checkpoint: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        if request.get("schema") != SCHEMA:
            raise PublicSettlementError("unsupported public settlement request")
        state: dict[str, Any] = dict(checkpoint)
        plan_value = state.get("plan")
        if isinstance(plan_value, dict):
            plan = plan_value
        else:
            plan = self._prepare_plan(request)
            state = self._checkpoint(state, on_checkpoint, "planned", plan=plan)
        if (
            plan.get("job_id") != request.get("job_id")
            or plan.get("receipt_id") != request.get("receipt_id")
            or plan.get("settlement_id") != request.get("settlement_id")
        ):
            raise PublicSettlementError("resumed settlement plan changed lifecycle identities")

        job_record_value = state.get("job_record")
        if isinstance(job_record_value, dict):
            job_record = job_record_value
        else:
            try:
                job_record = demo.verify_chain_bound_job(self.network, plan)
            except demo.DemoError as error:
                if not _missing_record(error):
                    raise
                open_txid = state.get("open_txid")
                if isinstance(open_txid, str):
                    demo.finalize_wwm_submission(self.network, open_txid)
                    job_record = demo.verify_chain_bound_job(self.network, plan)
                else:
                    def open_submitted(txid: str) -> None:
                        nonlocal state
                        state = self._checkpoint(
                            state,
                            on_checkpoint,
                            "open_submitted",
                            open_txid=txid,
                        )

                    opened = demo.submit_chain_bound_job(
                        self.hosted,
                        self.paths,
                        self.network,
                        plan,
                        open_submitted,
                    )
                    job_record = opened["record"]
                    state = {**state, "open_txid": opened["submission"]["txid"]}
            state = self._checkpoint(
                state,
                on_checkpoint,
                "open_finalized",
                job_record=job_record,
            )

        inference = _object(request, "inference")
        close_plan_value = state.get("close_plan")
        if isinstance(close_plan_value, dict):
            close_plan = close_plan_value
        else:
            close_plan = self._prepare_close(request, plan, job_record)
            state = self._checkpoint(
                state,
                on_checkpoint,
                "close_prepared",
                close_plan=close_plan,
            )

        try:
            records = demo.verify_chain_bound_close(
                self.network,
                plan,
                close_plan,
                job_record,
                inference,
            )
        except demo.DemoError as error:
            if not _missing_record(error):
                raise
            close_txid = state.get("close_txid")
            if isinstance(close_txid, str):
                demo.finalize_wwm_submission(self.network, close_txid)
                records = demo.verify_chain_bound_close(
                    self.network,
                    plan,
                    close_plan,
                    job_record,
                    inference,
                )
            else:
                def close_submitted(txid: str) -> None:
                    nonlocal state
                    state = self._checkpoint(
                        state,
                        on_checkpoint,
                        "close_submitted",
                        close_txid=txid,
                    )

                closed = demo.submit_chain_bound_close(
                    self.hosted,
                    self.paths,
                    self.network,
                    plan,
                    close_plan,
                    job_record,
                    inference,
                    close_submitted,
                )
                records = {
                    "receipt": closed["receipt"],
                    "settlement": closed["settlement"],
                }
                state = {**state, "close_txid": closed["submission"]["txid"]}
        state = self._checkpoint(
            state,
            on_checkpoint,
            "close_finalized",
            records=records,
        )
        return {
            "schema": RESULT_SCHEMA,
            "job_id": _text(request, "job_id", hex32=True),
            "receipt_id": _text(request, "receipt_id", hex32=True),
            "settlement_id": _text(request, "settlement_id", hex32=True),
            "open_transaction_id": state.get("open_txid"),
            "close_transaction_id": state.get("close_txid"),
            "job": job_record,
            "receipt": records["receipt"],
            "settlement": records["settlement"],
        }
