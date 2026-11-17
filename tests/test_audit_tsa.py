from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from nova.audit_anchor import ExternalAnchor
from nova.audit_tsa import (
    Rfc3161Error,
    Rfc3161Evidence,
    Rfc3161TimestampAnchorWriter,
    Rfc3161TsaConfig,
    verify_rfc3161_evidence,
)


def _evidence(response: bytes, digest: str = "a" * 64) -> Rfc3161Evidence:
    anchor_id = hashlib.sha256(response).hexdigest()
    return Rfc3161Evidence(
        anchor=ExternalAnchor(
            anchor_id=anchor_id,
            checkpoint_digest=digest,
            anchored_at="2026-09-15T00:00:00Z",
            custody_domain="tsa.example",
        ),
        request_der_b64=base64.b64encode(b"request").decode(),
        response_der_b64=base64.b64encode(response).decode(),
        ca_pem="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
    )


def test_tsa_config_requires_independent_https_trust_material() -> None:
    with pytest.raises(Rfc3161Error, match="HTTPS"):
        Rfc3161TsaConfig(url="http://tsa.example", custody_domain="tsa.example", ca_pem="CA")
    with pytest.raises(Rfc3161Error, match="trust anchor"):
        Rfc3161TsaConfig(url="https://tsa.example", custody_domain="tsa.example", ca_pem="")


def test_offline_evidence_rejects_checkpoint_digest_substitution(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _evidence(b"timestamp-response")
    monkeypatch.setattr("nova.audit_tsa._run_openssl", lambda *args, **kwargs: b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\nNonce: 42\n")
    with pytest.raises(Rfc3161Error, match="digest mismatch"):
        verify_rfc3161_evidence(evidence, expected_digest="b" * 64)


def test_offline_evidence_rejects_response_identity_tampering(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _evidence(b"timestamp-response")
    tampered = Rfc3161Evidence(
        anchor=evidence.anchor,
        request_der_b64=evidence.request_der_b64,
        response_der_b64=base64.b64encode(b"forged-response").decode(),
        ca_pem=evidence.ca_pem,
    )
    with pytest.raises(Rfc3161Error, match="identity mismatch"):
        verify_rfc3161_evidence(tampered, expected_digest="a" * 64)


def test_offline_evidence_verification_requires_real_tsa_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _evidence(b"timestamp-response")
    calls: list[tuple[str, ...]] = []

    def fake_openssl(*args: str, **kwargs: object) -> bytes:
        calls.append(args)
        if "-verify" in args:
            return b"Verification: OK"
        if args[:2] == ("ts", "-query"):
            return b"Nonce: 42\n"
        return b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\nNonce: 42\n"

    monkeypatch.setattr("nova.audit_tsa._run_openssl", fake_openssl)
    verify_rfc3161_evidence(evidence, expected_digest="a" * 64)
    assert any(args[:2] == ("ts", "-verify") for args in calls)
    assert any(args[:3] == ("ts", "-reply", "-in") for args in calls)


def test_timestamp_text_parsing_uses_a_real_file_not_platform_specific_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_openssl(*args: str, **kwargs: object) -> bytes:
        calls.append(args)
        return b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\nNonce: 42\n"

    monkeypatch.setattr("nova.audit_tsa._run_openssl", fake_openssl)
    from nova.audit_tsa import _timestamp_text

    assert _timestamp_text(b"timestamp-response") == ("2026-09-15 00:00:00Z", "1")
    assert len(calls) == 1
    assert calls[0][:2] == ("ts", "-reply")
    assert "/dev/stdin" not in calls[0]


def test_timestamp_writer_requires_nonce_and_embeds_tsa_certificate_request(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Rfc3161TsaConfig(
        url="https://tsa.example/tsp",
        custody_domain="tsa.example",
        ca_pem="CA",
    )
    calls: list[tuple[str, ...]] = []
    request_der = b"request-with-nonce-and-cert"
    response_der = b"timestamp-response"

    def fake_openssl(*args: str, **kwargs: object) -> bytes:
        calls.append(args)
        if "-out" in args:
            output = Path(args[args.index("-out") + 1])
            output.write_bytes(request_der)
            return b""
        if "-verify" in args:
            return b"Verification: OK"
        if args[:2] == ("ts", "-query"):
            return b"Nonce: 42\n"
        return b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\nNonce: 42\n"

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return response_der

    monkeypatch.setattr("nova.audit_tsa._run_openssl", fake_openssl)
    writer = Rfc3161TimestampAnchorWriter(config, opener=lambda request, timeout: FakeResponse())
    evidence = writer.publish_digest("a" * 64)

    query_calls = [args for args in calls if args[:3] == ("ts", "-query", "-digest")]
    assert len(query_calls) == 1
    assert "-no_nonce" not in query_calls[0]
    assert "-cert" in query_calls[0]
    assert evidence.request_der_b64 == base64.b64encode(request_der).decode()


def test_offline_evidence_rejects_mismatched_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _evidence(b"timestamp-response")

    def fake_openssl(*args: str, **kwargs: object) -> bytes:
        if "-verify" in args:
            return b"Verification: OK"
        if args[:2] == ("ts", "-query"):
            return b"Nonce: 42\n"
        return b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\nNonce: 43\n"

    monkeypatch.setattr("nova.audit_tsa._run_openssl", fake_openssl)
    with pytest.raises(Rfc3161Error, match="nonce mismatch"):
        verify_rfc3161_evidence(evidence, expected_digest="a" * 64)


def test_offline_evidence_rejects_missing_response_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = _evidence(b"timestamp-response")

    def fake_openssl(*args: str, **kwargs: object) -> bytes:
        if "-verify" in args:
            return b"Verification: OK"
        if args[:2] == ("ts", "-query"):
            return b"Nonce: 42\n"
        return b"Time stamp: 2026-09-15 00:00:00Z\nSerial number: 1\n"

    monkeypatch.setattr("nova.audit_tsa._run_openssl", fake_openssl)
    with pytest.raises(Rfc3161Error, match="response is missing nonce"):
        verify_rfc3161_evidence(evidence, expected_digest="a" * 64)
