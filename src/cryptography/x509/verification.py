# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.general_name import DNSName, IPAddress

__all__ = [
    "ClientVerifier",
    "PolicyBuilder",
    "CustomPolicyBuilder",
    "ExtensionValidatorNotPresent",
    "ExtensionValidatorMaybePresent",
    "ExtensionValidatorPresent",
    "ExtensionPolicy",
    "ServerVerifier",
    "Store",
    "Subject",
    "VerificationError",
    "VerifiedClient",
    "Criticality",
]

Store = rust_x509.Store
Subject = typing.Union[DNSName, IPAddress]
VerifiedClient = rust_x509.VerifiedClient
ClientVerifier = rust_x509.ClientVerifier
ServerVerifier = rust_x509.ServerVerifier
PolicyBuilder = rust_x509.PolicyBuilder
CustomPolicyBuilder = rust_x509.CustomPolicyBuilder
ExtensionValidatorNotPresent = rust_x509.ExtensionValidatorNotPresent
ExtensionValidatorMaybePresent = rust_x509.ExtensionValidatorMaybePresent
ExtensionValidatorPresent = rust_x509.ExtensionValidatorPresent
ExtensionPolicy = rust_x509.ExtensionPolicy
VerificationError = rust_x509.VerificationError
Criticality = rust_x509.Criticality
