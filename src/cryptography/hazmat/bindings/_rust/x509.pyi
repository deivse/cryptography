# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import typing

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.extensions import ExtensionType

def load_pem_x509_certificate(
    data: bytes, backend: typing.Any = None
) -> x509.Certificate: ...
def load_der_x509_certificate(
    data: bytes, backend: typing.Any = None
) -> x509.Certificate: ...
def load_pem_x509_certificates(
    data: bytes,
) -> list[x509.Certificate]: ...
def load_pem_x509_crl(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateRevocationList: ...
def load_der_x509_crl(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateRevocationList: ...
def load_pem_x509_csr(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateSigningRequest: ...
def load_der_x509_csr(
    data: bytes, backend: typing.Any = None
) -> x509.CertificateSigningRequest: ...
def encode_name_bytes(name: x509.Name) -> bytes: ...
def encode_extension_value(extension: x509.ExtensionType) -> bytes: ...
def create_x509_certificate(
    builder: x509.CertificateBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.Certificate: ...
def create_x509_csr(
    builder: x509.CertificateSigningRequestBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.CertificateSigningRequest: ...
def create_x509_crl(
    builder: x509.CertificateRevocationListBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    rsa_padding: PKCS1v15 | PSS | None,
) -> x509.CertificateRevocationList: ...

class Sct: ...
class Certificate: ...
class RevokedCertificate: ...
class CertificateRevocationList: ...
class CertificateSigningRequest: ...

class Criticality:
    NON_CRITICAL: Criticality
    AGNOSTIC: Criticality
    CRITICAL: Criticality

class ExtensionValidatorNotPresent:
    def __init__(self) -> None: ...

class ExtensionValidatorMaybePresent:
    def __init__(
        self,
        criticality: Criticality,
        validator: typing.Callable[[Policy, Certificate, ExtensionType], None]
        | None,
    ) -> None: ...

class ExtensionValidatorPresent:
    def __init__(
        self,
        criticality: Criticality,
        validator: typing.Callable[[Policy, Certificate, ExtensionType], None]
        | None,
    ) -> None: ...

ExtensionValidator = (
    ExtensionValidatorNotPresent
    | ExtensionValidatorMaybePresent
    | ExtensionValidatorPresent
)

class ExtensionPolicy:
    authority_information_access: ExtensionValidator
    authority_key_identifier: ExtensionValidator
    subject_key_identifier: ExtensionValidator
    key_usage: ExtensionValidator
    subject_alternative_name: ExtensionValidator
    basic_constraints: ExtensionValidator
    name_constraints: ExtensionValidator
    extended_key_usage: ExtensionValidator

    @staticmethod
    def permit_all() -> ExtensionPolicy: ...
    @staticmethod
    def web_pki_defaults_ca() -> ExtensionPolicy: ...
    @staticmethod
    def web_pki_defaults_ee() -> ExtensionPolicy: ...

class Policy:
    @property
    def max_chain_depth(self) -> int: ...
    @property
    def subject(self) -> x509.DNSName | x509.IPAddress | None: ...
    @property
    def validation_time(self) -> datetime.datetime: ...
    @property
    def extended_key_usage(self) -> x509.ObjectIdentifier: ...
    @property
    def minimum_rsa_modulus(self) -> int | None: ...

class PolicyBuilder:
    def time(self, new_time: datetime.datetime) -> PolicyBuilder: ...
    def store(self, new_store: Store) -> PolicyBuilder: ...
    def max_chain_depth(self, new_max_chain_depth: int) -> PolicyBuilder: ...
    def build_client_verifier(self) -> ClientVerifier: ...
    def build_server_verifier(
        self, subject: x509.verification.Subject
    ) -> ServerVerifier: ...

class CustomPolicyBuilder:
    def time(self, new_time: datetime.datetime) -> CustomPolicyBuilder: ...
    def store(self, new_store: Store) -> CustomPolicyBuilder: ...
    def max_chain_depth(
        self, new_max_chain_depth: int
    ) -> CustomPolicyBuilder: ...
    def eku(self, new_eku: x509.ObjectIdentifier) -> CustomPolicyBuilder: ...
    def ca_extension_policy(
        self, new_ca_extension_policy: ExtensionPolicy
    ) -> CustomPolicyBuilder: ...
    def ee_extension_policy(
        self, new_ee_extension_policy: ExtensionPolicy
    ) -> CustomPolicyBuilder: ...
    def build_client_verifier(self) -> ClientVerifier: ...
    def build_server_verifier(
        self, subject: x509.verification.Subject
    ) -> ServerVerifier: ...

class VerifiedClient:
    @property
    def subject(self) -> x509.Name: ...
    @property
    def sans(self) -> list[x509.GeneralName]: ...
    @property
    def chain(self) -> list[x509.Certificate]: ...

class ClientVerifier:
    @property
    def validation_time(self) -> datetime.datetime: ...
    @property
    def store(self) -> Store: ...
    @property
    def max_chain_depth(self) -> int: ...
    def verify(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
    ) -> VerifiedClient: ...

class ServerVerifier:
    @property
    def subject(self) -> x509.verification.Subject: ...
    @property
    def validation_time(self) -> datetime.datetime: ...
    @property
    def store(self) -> Store: ...
    @property
    def max_chain_depth(self) -> int: ...
    def verify(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
    ) -> list[x509.Certificate]: ...

class Store:
    def __init__(self, certs: list[x509.Certificate]) -> None: ...

class VerificationError(Exception):
    pass
