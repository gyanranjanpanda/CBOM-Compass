"""Protocols beyond TLS: live SSH, and configuration for SSH/IPsec/OpenVPN/S-MIME.

The live SSH test drives a real socket on loopback rather than mocking the
wire format, because the wire format is the part that can actually be wrong.
Nothing here reaches outside 127.0.0.1.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from cbom_compass.engine import run_scan
from cbom_compass.models import AssetType, QuantumStatus
from cbom_compass.policy import Policy
from cbom_compass.risk import classify_all, find_hybrid_partners
from cbom_compass.scanners.config import (ConfigScanner, parse_ike_proposal,
                                          parse_openssl_suite)
from cbom_compass.scanners.ssh import SSHScanner, parse_kexinit

DEPLOY = "samples/vulnerable-app/deploy"


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------
def build_kexinit(kex, host_keys, ciphers, macs) -> bytes:
    """A real SSH_MSG_KEXINIT payload, built the way a server builds one."""
    def name_list(items):
        raw = ",".join(items).encode()
        return struct.pack(">I", len(raw)) + raw

    payload = bytes([20]) + b"\x00" * 16
    payload += name_list(kex)
    payload += name_list(host_keys)
    payload += name_list(ciphers)          # c2s
    payload += name_list(ciphers)          # s2c
    payload += name_list(macs)             # c2s
    payload += name_list(macs)             # s2c
    payload += name_list(["none"]) * 2     # compression
    payload += name_list([]) * 2           # languages
    payload += b"\x00" + b"\x00" * 4       # first_kex_packet_follows + reserved
    return payload


def frame(payload: bytes) -> bytes:
    """Wrap a payload in the unencrypted binary packet framing."""
    padding_length = 8 - ((len(payload) + 5) % 8)
    if padding_length < 4:
        padding_length += 8
    packet_length = len(payload) + padding_length + 1
    return (struct.pack(">I", packet_length) + bytes([padding_length])
            + payload + b"\x00" * padding_length)


KEX = ["mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256",
       "diffie-hellman-group14-sha1"]
HOST_KEYS = ["rsa-sha2-512", "ssh-ed25519", "ssh-rsa"]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "3des-cbc"]
MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]


@pytest.fixture
def ssh_server():
    """A loopback listener that speaks just enough SSH to be inventoried."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    banner = b"SSH-2.0-OpenSSH_9.9p1 Debian-3\r\n"

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.sendall(banner)
                conn.recv(512)                 # the client's identification
                conn.sendall(frame(build_kexinit(KEX, HOST_KEYS, CIPHERS, MACS)))
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    listener.close()
    thread.join(timeout=2)


def test_live_ssh_probe_reads_the_offered_algorithms(ssh_server):
    scanner = SSHScanner(Policy(scan_allowlist=["127.0.0.1"]))
    result = scanner.scan(f"127.0.0.1:{ssh_server}")
    assert not result.errors
    found = {a.algorithm for a in result.assets}
    assert {"SSH-2.0", "ML-KEM", "ECDH", "DH", "RSA", "EdDSA",
            "ChaCha20", "AES", "3DES", "HMAC"} <= found


def test_ssh_reports_the_whole_accepted_set_not_one_negotiated_suite(ssh_server):
    """The distinction from tls.py: KEXINIT announces everything on offer."""
    scanner = SSHScanner(Policy(scan_allowlist=["127.0.0.1"]))
    result = scanner.scan(f"127.0.0.1:{ssh_server}")
    protocol = next(a for a in result.assets if a.asset_type is AssetType.PROTOCOL)
    offered = protocol.evidence[0].detail["offered"]
    assert offered["kex_algorithms"] == KEX
    assert offered["server_host_key_algorithms"] == HOST_KEYS
    # Three ciphers offered, three cipher assets — not just the one picked.
    ciphers = [a for a in result.assets
               if a.evidence[0].detail.get("category") == "cipher"]
    assert len(ciphers) == 3


def test_ssh_rsa_is_kept_apart_from_rsa_sha2(ssh_server):
    """`ssh-rsa` is RSA-with-SHA-1 and is a different finding."""
    scanner = SSHScanner(Policy(scan_allowlist=["127.0.0.1"]))
    result = scanner.scan(f"127.0.0.1:{ssh_server}")
    hashes = {a.parameters.get("signature_hash")
              for a in result.assets if a.algorithm == "RSA"}
    assert hashes == {"SHA-1", "SHA-512"}


def test_ssh_hybrid_kex_discounts_only_its_own_classical_half(ssh_server):
    """The bare curve25519-sha256 offered alongside must stay exposed."""
    scanner = SSHScanner(Policy(scan_allowlist=["127.0.0.1"]))
    result = scanner.scan(f"127.0.0.1:{ssh_server}")
    risks = classify_all(result.assets, Policy(z_year=2035), 2026)
    x25519 = [a for a in result.assets
              if a.algorithm == "ECDH" and a.parameters.get("curve") == "x25519"]
    assert len(x25519) == 2          # the hybrid half and the standalone one
    scores = sorted(risks[a.id].score for a in x25519)
    assert scores[0] < 0.1           # hybrid half, discounted
    assert scores[1] > 0.3           # standalone, still urgent


def test_ssh_endpoint_outside_the_allowlist_is_refused(ssh_server):
    result = SSHScanner(Policy(scan_allowlist=["example.com"])).scan(
        f"127.0.0.1:{ssh_server}")
    assert result.assets == []
    assert result.errors and "refused" in result.errors[0].message


def test_ssh_scheme_prefix_and_default_port_are_accepted():
    scanner = SSHScanner(Policy(scan_allowlist=["nothing"]))
    refused = scanner.scan("ssh://blocked.example.com")
    assert "refused" in refused.errors[0].message


def test_kexinit_parser_rejects_a_non_kexinit_message():
    with pytest.raises(ValueError, match="KEXINIT"):
        parse_kexinit(bytes([21]) + b"\x00" * 32)


def test_kexinit_parser_survives_a_truncated_payload():
    """A short read must lose the tail, not raise."""
    full = build_kexinit(KEX, HOST_KEYS, CIPHERS, MACS)
    lists = parse_kexinit(full[: len(full) // 2])
    assert lists["kex_algorithms"] == KEX
    assert "languages_server_to_client" not in lists


# ---------------------------------------------------------------------------
# Configuration files
# ---------------------------------------------------------------------------
def test_sshd_config_yields_the_configured_algorithms():
    result = ConfigScanner().scan(f"{DEPLOY}/sshd_config")
    found = {(a.algorithm, a.parameters.get("mode") or a.parameters.get("hash")
              or a.parameters.get("curve") or a.parameters.get("signature_hash"))
             for a in result.assets}
    assert ("3DES", "CBC") in found
    assert ("HMAC", "SHA-1") in found
    assert ("RSA", "SHA-1") in found
    assert ("ML-KEM", None) in found


def test_a_removal_list_is_not_an_inventory():
    """`PubkeyAcceptedAlgorithms -ssh-dss` disables DSA. It is not in use."""
    result = ConfigScanner().scan(f"{DEPLOY}/sshd_config")
    assert not any(a.algorithm == "DSA" for a in result.assets)


def test_ike_proposals_decompose_into_their_three_parts():
    parts = parse_ike_proposal("aes256-sha256-modp2048!")
    assert ("AES", 256, {"mode": "CBC"}) in parts
    assert ("HMAC", None, {"hash": "SHA-256"}) in parts
    assert ("DH", 2048, {}) in parts


def test_ipsec_config_separates_encryption_from_key_agreement():
    """AES-256 needs nothing; modp1024 is the finding."""
    result = ConfigScanner().scan(f"{DEPLOY}/ipsec.conf")
    risks = classify_all(result.assets, Policy(z_year=2035), 2026)
    dh = next(a for a in result.assets if a.algorithm == "DH" and a.key_size == 1024)
    aes = next(a for a in result.assets if a.algorithm == "AES" and a.key_size == 256)
    assert risks[dh.id].quantum_status is QuantumStatus.BROKEN
    assert risks[aes.id].quantum_status is QuantumStatus.ADEQUATE
    assert risks[dh.id].score > risks[aes.id].score


def test_strongswan_pqc_round_is_recognised_as_a_hybrid():
    result = ConfigScanner().scan(f"{DEPLOY}/ipsec.conf")
    partners = find_hybrid_partners(result.assets)
    ecdh = next(a for a in result.assets
                if a.algorithm == "ECDH" and a.parameters.get("hybrid_with"))
    assert partners[ecdh.id] == "ML-KEM"


def test_openvpn_directives_are_read():
    result = ConfigScanner().scan(f"{DEPLOY}/client.ovpn")
    found = {(a.algorithm, a.key_size) for a in result.assets}
    assert ("Blowfish", None) in found          # 64-bit block on a long tunnel
    assert ("AES", 256) in found
    assert ("HMAC", None) in found


def test_web_server_protocol_versions_become_protocol_assets():
    result = ConfigScanner().scan(f"{DEPLOY}/nginx.conf")
    protocols = {a.algorithm for a in result.assets
                 if a.asset_type is AssetType.PROTOCOL}
    assert {"TLSv1.1", "TLSv1.2", "TLSv1.3"} <= protocols
    risks = classify_all(result.assets, Policy(), 2026)
    old = next(a for a in result.assets if a.algorithm == "TLSv1.1")
    assert risks[old.id].quantum_status is QuantumStatus.DEPRECATED_INSUFFICIENT


def test_cipher_suite_exclusions_are_not_inventoried():
    """`!aNULL` removes a suite; it is not a configured algorithm."""
    result = ConfigScanner().scan(f"{DEPLOY}/nginx.conf")
    assert all(not a.algorithm.startswith("!") for a in result.assets)


def test_openssl_suite_decomposition():
    parts = parse_openssl_suite("ECDHE-RSA-AES256-GCM-SHA384")
    assert ("ECDH", None, {}) in parts
    assert ("RSA", None, {}) in parts
    assert ("AES", 256, {}) in parts
    assert parse_openssl_suite("TLS_AES_128_GCM_SHA256") == [("AES", 128, {})]


def test_smime_markers_produce_a_protocol_and_its_algorithm(tmp_path):
    source = tmp_path / "Mailer.java"
    source.write_text(
        "import org.bouncycastle.cms.CMSAlgorithm;\n"
        "SMIMEEnvelopedGenerator gen = new SMIMEEnvelopedGenerator();\n"
        "gen.generate(msg, CMSAlgorithm.DES_EDE3_CBC);\n"
    )
    # S/MIME markers are looked for in every config file, and the openssl.cnf
    # rule is what pulls a mail configuration into scope.
    config = tmp_path / "openssl.cnf"
    config.write_text('[ smime ]\n# openssl smime -sign -des3 -signer cert.pem\n')
    result = ConfigScanner().scan(str(tmp_path))
    protocols = {a.algorithm for a in result.assets
                 if a.asset_type is AssetType.PROTOCOL}
    assert "S/MIME" in protocols
    assert any(a.algorithm == "3DES" for a in result.assets)


def test_config_findings_are_medium_confidence():
    """A configuration lists what is permitted, not what was negotiated."""
    result = ConfigScanner().scan(f"{DEPLOY}/sshd_config")
    algorithms = [a for a in result.assets if a.asset_type is AssetType.ALGORITHM]
    assert algorithms and all(a.confidence.value == "medium" for a in algorithms)


def test_config_scanner_ignores_files_that_are_not_configuration(tmp_path):
    (tmp_path / "notes.txt").write_text("Ciphers aes128-cbc\n")
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    assert ConfigScanner().scan(str(tmp_path)).assets == []


def test_config_scanner_is_wired_into_the_engine():
    report = run_scan({"config": [DEPLOY]}, Policy())
    assert report.run.sources_covered == ["config"]
    assert any(a.asset_type is AssetType.PROTOCOL for a in report.inventory.assets)


def test_a_missing_path_is_an_error_not_a_crash():
    result = ConfigScanner().scan("does/not/exist")
    assert result.assets == []
    assert result.errors


# ---------------------------------------------------------------------------
# Protocol containers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("protocol", ["SSH-2.0", "IPsec", "OpenVPN", "S/MIME"])
def test_protocol_containers_are_not_scored_twice(protocol):
    """The exposure belongs to the negotiated algorithms, not the container.

    Scoring the container as well would double-count every key exchange and
    cipher underneath it, and leaving it UNKNOWN would put it in the 'review
    manually' bucket on the Overview where it does not belong.
    """
    from cbom_compass.knowledge.algorithms import classify
    result = classify(protocol)
    assert result.quantum_status is QuantumStatus.ADEQUATE
    assert result.primitive == "protocol"


def test_ssh_protocol_1_is_not_upgraded_to_ssh_2():
    """Longest-prefix normalisation would strip `ssh-1` to `ssh`."""
    from cbom_compass.knowledge.algorithms import classify, normalise
    assert normalise("ssh-1.5") == "SSH-1"
    assert classify("SSH-1").quantum_status is QuantumStatus.BROKEN_CLASSICAL


def test_no_configured_protocol_lands_in_the_unknown_bucket():
    report = run_scan({"config": [DEPLOY]}, Policy())
    unknown = [a for a in report.inventory.assets
               if report.risks[a.id].quantum_status is QuantumStatus.UNKNOWN]
    assert unknown == [], [a.algorithm for a in unknown]
