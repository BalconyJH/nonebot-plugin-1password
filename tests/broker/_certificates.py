"""Ephemeral certificate authority and mTLS identities for Broker tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class BrokerTestCertificates:
    """Paths and client fingerprint for one isolated test authority."""

    ca: Path
    server_certificate: Path
    server_private_key: Path
    client_certificate: Path
    client_private_key: Path
    unlisted_client_certificate: Path
    unlisted_client_private_key: Path
    client_fingerprint: str
    unlisted_client_fingerprint: str


@dataclass(frozen=True, slots=True)
class _Issuer:
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    now: datetime


def create_test_certificates(directory: Path) -> BrokerTestCertificates:
    """Create one CA plus server, allowed-client, and unlisted-client identities."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NB1P Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key, server_certificate = _identity(
        common_name="localhost",
        issuer=_Issuer(ca_key, ca_certificate, now),
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        subject_alternative_name=x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
        ),
    )
    client_key, client_certificate = _identity(
        common_name="nonebot-primary",
        issuer=_Issuer(ca_key, ca_certificate, now),
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    unlisted_key, unlisted_certificate = _identity(
        common_name="nonebot-unlisted",
        issuer=_Issuer(ca_key, ca_certificate, now),
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )

    ca_path = directory / "ca.pem"
    server_certificate_path = directory / "server.pem"
    server_private_key_path = directory / "server.key"
    client_certificate_path = directory / "client.pem"
    client_private_key_path = directory / "client.key"
    unlisted_certificate_path = directory / "unlisted.pem"
    unlisted_private_key_path = directory / "unlisted.key"
    _write_certificate(ca_path, ca_certificate)
    _write_identity(
        server_certificate_path, server_private_key_path, server_certificate, server_key
    )
    _write_identity(
        client_certificate_path, client_private_key_path, client_certificate, client_key
    )
    _write_identity(
        unlisted_certificate_path,
        unlisted_private_key_path,
        unlisted_certificate,
        unlisted_key,
    )
    return BrokerTestCertificates(
        ca=ca_path,
        server_certificate=server_certificate_path,
        server_private_key=server_private_key_path,
        client_certificate=client_certificate_path,
        client_private_key=client_private_key_path,
        unlisted_client_certificate=unlisted_certificate_path,
        unlisted_client_private_key=unlisted_private_key_path,
        client_fingerprint=client_certificate.fingerprint(hashes.SHA256()).hex(),
        unlisted_client_fingerprint=unlisted_certificate.fingerprint(
            hashes.SHA256()
        ).hex(),
    )


def _identity(
    *,
    common_name: str,
    issuer: _Issuer,
    usage: x509.ObjectIdentifier,
    subject_alternative_name: x509.SubjectAlternativeName | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issuer.now - timedelta(minutes=1))
        .not_valid_after(issuer.now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if subject_alternative_name is not None:
        builder = builder.add_extension(subject_alternative_name, critical=False)
    return key, builder.sign(issuer.key, hashes.SHA256())


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _write_identity(
    certificate_path: Path,
    key_path: Path,
    certificate: x509.Certificate,
    key: ec.EllipticCurvePrivateKey,
) -> None:
    _write_certificate(certificate_path, certificate)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


__all__ = ["BrokerTestCertificates", "create_test_certificates"]
