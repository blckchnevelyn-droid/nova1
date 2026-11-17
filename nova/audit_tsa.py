"""RFC 3161 external timestamp anchoring for Nova audit checkpoints.

This adapter sends only a checkpoint digest to an independently operated RFC 3161
Time-Stamping Authority (TSA). The returned timestamp response is retained as
portable evidence and is verified offline with OpenSSL against explicitly supplied
TSA trust material. The TSA is an external trust domain; Nova never treats its own
SQLite state or checkpoint signing key as the timestamp trust root.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nova.audit_anchor import AuditAnchorError, ExternalAnchor


class Rfc3161Error(AuditAnchorError):
    """Raised when an RFC 3161 anchor cannot be created or independently verified."""


@dataclass(frozen=True)
class Rfc3161Evidence:
    """Portable evidence required to re-verify an external timestamp offline."""

    anchor: ExternalAnchor
    request_der_b64: str
    response_der_b64: str
    ca_pem: str
    untrusted_chain_pem: str = ""


@dataclass(frozen=True)
class Rfc3161TsaConfig:
    """Configuration for one explicitly trusted RFC 3161 TSA."""

    url: str
    custody_domain: str
    ca_pem: str
    untrusted_chain_pem: str = ""
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise Rfc3161Error("TSA endpoint must use HTTPS")
        if not self.custody_domain:
            raise Rfc3161Error("TSA custody domain is required")
        if self.timeout_seconds <= 0:
            raise Rfc3161Error("TSA timeout must be positive")
        if not self.ca_pem.strip():
            raise Rfc3161Error("TSA trust anchor is required")


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    import base64

    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise Rfc3161Error("timestamp evidence encoding is invalid") from exc


def _run_openssl(*args: str, stdin: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise Rfc3161Error("openssl is required for RFC 3161 verification") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise Rfc3161Error(f"openssl timestamp operation failed: {detail or 'unknown error'}")
    return result.stdout


def _timestamp_text(response_der: bytes) -> tuple[str, str]:
    """Extract timestamp metadata using a portable temporary DER file."""
    with tempfile.TemporaryDirectory(prefix="nova-tsa-text-") as temp_dir:
        response_path = Path(temp_dir) / "response.tsr"
        response_path.write_bytes(response_der)
        text = _run_openssl("ts", "-reply", "-in", str(response_path), "-text").decode(
            "utf-8", errors="replace"
        )
    stamp = re.search(r"^Time stamp:\s*(.+)$", text, re.MULTILINE)
    serial = re.search(r"^Serial number:\s*(.+)$", text, re.MULTILINE)
    if not stamp or not serial:
        raise Rfc3161Error("timestamp response is missing RFC 3161 timestamp metadata")
    return stamp.group(1).strip(), serial.group(1).strip()


def _extract_nonce(text: str, *, label: str) -> str:
    """Extract the RFC 3161 nonce from OpenSSL's canonical text representation."""
    match = re.search(r"^Nonce:\s*(.+)$", text, re.MULTILINE)
    if not match or not match.group(1).strip():
        raise Rfc3161Error(f"RFC 3161 {label} is missing nonce")
    return match.group(1).strip().lower()


def _request_nonce(request_der: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="nova-tsa-query-text-") as temp_dir:
        request_path = Path(temp_dir) / "request.tsq"
        request_path.write_bytes(request_der)
        text = _run_openssl("ts", "-query", "-in", str(request_path), "-text").decode(
            "utf-8", errors="replace"
        )
    return _extract_nonce(text, label="request")


def _response_nonce(response_der: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="nova-tsa-response-text-") as temp_dir:
        response_path = Path(temp_dir) / "response.tsr"
        response_path.write_bytes(response_der)
        text = _run_openssl("ts", "-reply", "-in", str(response_path), "-text").decode(
            "utf-8", errors="replace"
        )
    return _extract_nonce(text, label="response")


def _verify_nonce_binding(request_der: bytes, response_der: bytes) -> None:
    request_nonce = _request_nonce(request_der)
    response_nonce = _response_nonce(response_der)
    if request_nonce != response_nonce:
        raise Rfc3161Error("RFC 3161 nonce mismatch")


class Rfc3161TimestampAnchorWriter:
    """Publishes checkpoint digests to an RFC 3161 TSA and returns portable evidence."""

    def __init__(
        self,
        config: Rfc3161TsaConfig,
        *,
        opener: Callable[[urllib.request.Request, float], object] | None = None,
    ) -> None:
        self._config = config
        self._opener = opener or (lambda request, timeout: urllib.request.urlopen(request, timeout=timeout))

    def publish_digest(self, checkpoint_digest: str) -> Rfc3161Evidence:
        if len(checkpoint_digest) != 64 or any(c not in "0123456789abcdef" for c in checkpoint_digest):
            raise Rfc3161Error("checkpoint digest must be a lowercase SHA-256 hex digest")
        with tempfile.TemporaryDirectory(prefix="nova-tsa-") as temp_dir:
            request_path = Path(temp_dir) / "request.tsq"
            _run_openssl(
                "ts",
                "-query",
                "-digest",
                checkpoint_digest,
                "-sha256",
                "-cert",
                "-out",
                str(request_path),
            )
            try:
                request_der = request_path.read_bytes()
            except OSError as exc:
                raise Rfc3161Error("failed to read generated timestamp request") from exc
            if not request_der:
                raise Rfc3161Error("failed to generate timestamp request")
        request = urllib.request.Request(
            self._config.url,
            data=request_der,
            headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
            method="POST",
        )
        try:
            with self._opener(request, self._config.timeout_seconds) as response:
                response_der = response.read()
        except (urllib.error.URLError, OSError) as exc:
            raise Rfc3161Error("RFC 3161 TSA request failed") from exc
        if not response_der:
            raise Rfc3161Error("RFC 3161 TSA returned an empty response")
        self._verify_response(request_der, response_der)
        anchored_at, _serial = _timestamp_text(response_der)
        anchor_id = hashlib.sha256(response_der).hexdigest()
        anchor = ExternalAnchor(
            anchor_id=anchor_id,
            checkpoint_digest=checkpoint_digest,
            anchored_at=anchored_at,
            custody_domain=self._config.custody_domain,
        )
        return Rfc3161Evidence(
            anchor=anchor,
            request_der_b64=_b64(request_der),
            response_der_b64=_b64(response_der),
            ca_pem=self._config.ca_pem,
            untrusted_chain_pem=self._config.untrusted_chain_pem,
        )

    def _verify_response(self, request_der: bytes, response_der: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="nova-tsa-verify-") as temp_dir:
            root = Path(temp_dir)
            request_path = root / "request.tsq"
            response_path = root / "response.tsr"
            ca_path = root / "ca.pem"
            chain_path = root / "chain.pem"
            request_path.write_bytes(request_der)
            response_path.write_bytes(response_der)
            ca_path.write_text(self._config.ca_pem, encoding="utf-8")
            args = ["ts", "-verify", "-in", str(response_path), "-queryfile", str(request_path), "-CAfile", str(ca_path)]
            if self._config.untrusted_chain_pem:
                chain_path.write_text(self._config.untrusted_chain_pem, encoding="utf-8")
                args.extend(["-untrusted", str(chain_path)])
            _run_openssl(*args)
        _verify_nonce_binding(request_der, response_der)


def verify_rfc3161_evidence(evidence: Rfc3161Evidence, *, expected_digest: str) -> None:
    """Verify the retained RFC 3161 receipt without trusting Nova's database."""
    if evidence.anchor.checkpoint_digest != expected_digest:
        raise Rfc3161Error("timestamp anchor digest mismatch")
    response_der = _unb64(evidence.response_der_b64)
    request_der = _unb64(evidence.request_der_b64)
    if hashlib.sha256(response_der).hexdigest() != evidence.anchor.anchor_id:
        raise Rfc3161Error("timestamp anchor identity mismatch")
    with tempfile.TemporaryDirectory(prefix="nova-tsa-offline-") as temp_dir:
        root = Path(temp_dir)
        request_path = root / "request.tsq"
        response_path = root / "response.tsr"
        ca_path = root / "ca.pem"
        request_path.write_bytes(request_der)
        response_path.write_bytes(response_der)
        ca_path.write_text(evidence.ca_pem, encoding="utf-8")
        args = ["ts", "-verify", "-in", str(response_path), "-queryfile", str(request_path), "-CAfile", str(ca_path)]
        if evidence.untrusted_chain_pem:
            chain_path = root / "chain.pem"
            chain_path.write_text(evidence.untrusted_chain_pem, encoding="utf-8")
            args.extend(["-untrusted", str(chain_path)])
        _run_openssl(*args)
    _verify_nonce_binding(request_der, response_der)
    _timestamp_text(response_der)
