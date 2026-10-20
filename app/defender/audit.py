"""Cryptographic audit chain and canonical verification for security events.

Provides SHA-256 hash chaining, deterministic canonical serialization,
genesis hash constants, and cryptographic integrity verification over the
in-memory security event audit stream.

SECURITY & THREAT MODEL DISCLOSURE:
-----------------------------------
This audit chain operates in-memory within the DefenderService process space.
It guarantees strict tamper-evidence against uncoordinated modifications,
deletions, insertions, and reordering within active runtime memory.
HOWEVER:
1. An in-memory chain DOES NOT survive application restarts or server reboots.
2. An adversary with direct operating-system write access to the host Python process
   memory (or debugger attachment) could, in principle, rewrite the entire chain
   and recalculate all hashes from the point of tampering forward.
3. Durable, immutable tamper-proofing requires an append-only remote syslog datastore,
   write-once-read-many (WORM) hardware, or an external decentralized ledger.
   Do not claim durable tamper-proof storage without persistent infrastructure.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Sequence
from pydantic import BaseModel, Field

# Genesis hash: 64 hexadecimal zeros representing the root of the cryptographic chain
GENESIS_HASH: str = "0" * 64


class AuditChainVerificationResponse(BaseModel):
    """Result schema for cryptographic audit chain verification."""

    valid: bool = Field(
        ...,
        description="True if the entire audit chain is cryptographically intact and unbroken",
    )
    total_events: int = Field(
        ...,
        description="Total number of security events evaluated in the audit chain",
    )
    genesis_hash: str = Field(
        default=GENESIS_HASH,
        description="Genesis previous-hash constant anchoring the chain root",
    )
    latest_event_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the most recent event, or None if chain is empty",
    )
    verified_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC ISO timestamp of verification execution",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error code if verification failed: HASH_MISMATCH, CHAIN_BROKEN, or INVALID_DATA",
    )
    failed_event_index: Optional[int] = Field(
        default=None,
        description="Zero-based index of the first failing event, if validation failed",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic details, reason strings, and expected vs actual hashes",
    )
    disclaimer: str = Field(
        default=(
            "In-memory cryptographic chain. Verifies runtime integrity and tamper-evidence in active memory. "
            "Does not survive process restarts and cannot prevent an attacker with full memory write access "
            "from recalculating the entire chain. Durable tamper-proofing requires persistent append-only storage."
        ),
        description="Security operating boundaries and threat model disclosure",
    )


def default_json_serializer(obj: Any) -> Any:
    """Fallback serializer for non-standard data types within event metadata."""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, (set, frozenset)):
        return sorted(list(obj))
    return str(obj)


def canonical_event_bytes(
    timestamp: str,
    step: int,
    event_type: str,
    severity: str,
    source: str,
    message: str,
    metadata: Dict[str, Any],
    prev_hash: str,
) -> bytes:
    """Generate deterministic, canonical UTF-8 JSON bytes for an event payload.
    
    Guarantees consistent SHA-256 hashing by:
    - Sorting dictionary keys lexicographically at all nesting depths
    - Eliminating variable whitespace between separators
    - Ensuring ASCII-escaped string encoding
    - Incorporating prev_hash to bind the chain sequence
    """
    payload = {
        "event_type": event_type,
        "message": message,
        "metadata": metadata if metadata is not None else {},
        "prev_hash": prev_hash,
        "severity": severity,
        "source": source,
        "step": step,
        "timestamp": timestamp,
    }
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=default_json_serializer,
    )
    return canonical_json.encode("utf-8")


def compute_event_hash(
    timestamp: str,
    step: int,
    event_type: str,
    severity: str,
    source: str,
    message: str,
    metadata: Dict[str, Any],
    prev_hash: str,
) -> str:
    """Compute cryptographic SHA-256 digest of canonical event payload."""
    data_bytes = canonical_event_bytes(
        timestamp=timestamp,
        step=step,
        event_type=event_type,
        severity=severity,
        source=source,
        message=message,
        metadata=metadata,
        prev_hash=prev_hash,
    )
    return hashlib.sha256(data_bytes).hexdigest()


def verify_audit_chain(
    events: Sequence[Any],
    genesis_hash: str = GENESIS_HASH,
) -> AuditChainVerificationResponse:
    """Cryptographically verify an audit chain sequence of SecurityEvent objects.

    Validates:
    1. Empty chains are trivially valid.
    2. Event 0 has prev_hash matching genesis_hash.
    3. For every subsequent event i > 0, event[i].prev_hash matches event[i-1].event_hash.
    4. For every event i, event[i].event_hash exactly matches recomputed canonical SHA-256 hash.
    5. Detects any content tampering, item insertion, item deletion, or reordering.

    Returns:
        AuditChainVerificationResponse with validation status and diagnostics.
    """
    now = datetime.now(timezone.utc).isoformat()
    total = len(events)

    if total == 0:
        return AuditChainVerificationResponse(
            valid=True,
            total_events=0,
            genesis_hash=genesis_hash,
            latest_event_hash=None,
            verified_at=now,
            error=None,
            failed_event_index=None,
            details={"message": "Audit chain is empty; trivially valid."},
        )

    expected_prev = genesis_hash

    for idx, event in enumerate(events):
        event_prev = getattr(event, "prev_hash", None)
        event_hash = getattr(event, "event_hash", None)

        # 1. Validate previous hash link
        if not event_prev or not hmac.compare_digest(event_prev, expected_prev):
            return AuditChainVerificationResponse(
                valid=False,
                total_events=total,
                genesis_hash=genesis_hash,
                latest_event_hash=getattr(events[-1], "event_hash", None),
                verified_at=now,
                error="CHAIN_BROKEN",
                failed_event_index=idx,
                details={
                    "reason": (
                        f"Event at index {idx} has prev_hash '{event_prev}' but expected '{expected_prev}'. "
                        f"Chain sequence broken (possible deletion, insertion, or reordering)."
                    ),
                    "expected_prev_hash": expected_prev,
                    "actual_prev_hash": event_prev,
                    "event_step": getattr(event, "step", None),
                    "event_type": getattr(event, "event_type", None),
                },
            )

        # 2. Recompute and validate event payload hash
        computed_hash = compute_event_hash(
            timestamp=getattr(event, "timestamp", ""),
            step=getattr(event, "step", 0),
            event_type=getattr(event, "event_type", ""),
            severity=getattr(event, "severity", "INFO"),
            source=getattr(event, "source", "DefenderService"),
            message=getattr(event, "message", ""),
            metadata=getattr(event, "metadata", {}),
            prev_hash=event_prev,
        )

        if not event_hash or not hmac.compare_digest(event_hash, computed_hash):
            return AuditChainVerificationResponse(
                valid=False,
                total_events=total,
                genesis_hash=genesis_hash,
                latest_event_hash=getattr(events[-1], "event_hash", None),
                verified_at=now,
                error="HASH_MISMATCH",
                failed_event_index=idx,
                details={
                    "reason": (
                        f"Event at index {idx} payload does not match its stored event_hash. "
                        f"Event content has been altered or tampered with."
                    ),
                    "expected_event_hash": computed_hash,
                    "actual_event_hash": event_hash,
                    "event_step": getattr(event, "step", None),
                    "event_type": getattr(event, "event_type", None),
                },
            )

        expected_prev = event_hash

    return AuditChainVerificationResponse(
        valid=True,
        total_events=total,
        genesis_hash=genesis_hash,
        latest_event_hash=getattr(events[-1], "event_hash", None),
        verified_at=now,
        error=None,
        failed_event_index=None,
        details={
            "verified_count": total,
            "chain_start": getattr(events[0], "event_hash", None),
            "chain_end": getattr(events[-1], "event_hash", None),
        },
    )
