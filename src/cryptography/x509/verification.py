# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.extensions import ExtensionType
from cryptography.x509.general_name import DNSName, IPAddress

__all__ = [
    "ClientVerifier",
    "PolicyBuilder",
    "CustomPolicyBuilder",
    "ExtensionValidator",
    "ExtensionPolicy",
    "Policy",
    "ServerVerifier",
    "Store",
    "Subject",
    "VerificationError",
    "VerifiedClient",
    "Criticality",
]

# TODO: Consider moving custom verification to
# x509.verification.custom or cryptography.hazmat.x509.custom_verification

Store = rust_x509.Store
Subject = typing.Union[DNSName, IPAddress]
VerifiedClient = rust_x509.VerifiedClient
ClientVerifier = rust_x509.ClientVerifier
ServerVerifier = rust_x509.ServerVerifier
PolicyBuilder = rust_x509.PolicyBuilder
CustomPolicyBuilder = rust_x509.CustomPolicyBuilder
Policy = rust_x509.Policy
ExtensionPolicy = rust_x509.ExtensionPolicy
VerificationError = rust_x509.VerificationError
Criticality = rust_x509.Criticality


class ExtensionValidator:
    @staticmethod
    def not_present():
        return rust_x509.ExtensionValidatorNotPresent()

    @staticmethod
    def maybe_present(
        criticality: Criticality,
        validator: typing.Callable[
            [rust_x509.Policy, rust_x509.Certificate, ExtensionType], None
        ]
        | None,
    ):
        return rust_x509.ExtensionValidatorMaybePresent(criticality, validator)

    @staticmethod
    def present(
        criticality: Criticality,
        validator: typing.Callable[
            [rust_x509.Policy, rust_x509.Certificate, ExtensionType], None
        ]
        | None,
    ):
        return rust_x509.ExtensionValidatorPresent(criticality, validator)
