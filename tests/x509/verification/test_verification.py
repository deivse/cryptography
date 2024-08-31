# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import os
from functools import lru_cache
from ipaddress import IPv4Address

import pytest

from cryptography import x509
from cryptography.hazmat._oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
)
from cryptography.x509.base import Certificate
from cryptography.x509.general_name import DNSName, IPAddress
from cryptography.x509.verification import (
    Criticality,
    CustomPolicyBuilder,
    ExtensionPolicy,
    ExtensionValidator,
    Policy,
    PolicyBuilder,
    Store,
    VerificationError,
)
from tests.x509.test_x509 import _load_cert


@lru_cache(maxsize=1)
def dummy_store() -> Store:
    cert = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    return Store([cert])


@pytest.mark.parametrize("builder_type", [PolicyBuilder, CustomPolicyBuilder])
class TestPolicyBuilderCommon:
    """
    Tests functionality that is identical between
    PolicyBuilder and CustomPolicyBuilder.
    """

    def test_time_already_set(self, builder_type):
        with pytest.raises(ValueError):
            builder_type().time(datetime.datetime.now()).time(
                datetime.datetime.now()
            )

    def test_store_already_set(self, builder_type):
        with pytest.raises(ValueError):
            builder_type().store(dummy_store()).store(dummy_store())

    def test_max_chain_depth_already_set(self, builder_type):
        with pytest.raises(ValueError):
            builder_type().max_chain_depth(8).max_chain_depth(9)

    def test_ipaddress_subject(self, builder_type):
        policy = (
            builder_type()
            .store(dummy_store())
            .build_server_verifier(IPAddress(IPv4Address("0.0.0.0")))
        )
        assert policy.subject == IPAddress(IPv4Address("0.0.0.0"))

    def test_dnsname_subject(self, builder_type):
        policy = (
            builder_type()
            .store(dummy_store())
            .build_server_verifier(DNSName("cryptography.io"))
        )
        assert policy.subject == DNSName("cryptography.io")

    def test_subject_bad_types(self, builder_type):
        # Subject must be a supported GeneralName type
        with pytest.raises(TypeError):
            builder_type().store(dummy_store()).build_server_verifier(
                "cryptography.io"
            )
        with pytest.raises(TypeError):
            builder_type().store(dummy_store()).build_server_verifier(
                "0.0.0.0"
            )
        with pytest.raises(TypeError):
            builder_type().store(dummy_store()).build_server_verifier(
                IPv4Address("0.0.0.0")
            )
        with pytest.raises(TypeError):
            builder_type().store(dummy_store()).build_server_verifier(None)

    def test_builder_pattern(self, builder_type):
        now = datetime.datetime.now().replace(microsecond=0)
        store = dummy_store()
        max_chain_depth = 16

        builder = builder_type()
        builder = builder.time(now)
        builder = builder.store(store)
        builder = builder.max_chain_depth(max_chain_depth)

        verifier = builder.build_server_verifier(DNSName("cryptography.io"))
        assert verifier.subject == DNSName("cryptography.io")
        assert verifier.validation_time == now
        assert verifier.store == store
        assert verifier.max_chain_depth == max_chain_depth

    def test_build_server_verifier_missing_store(self, builder_type):
        with pytest.raises(
            ValueError, match="A server verifier must have a trust store"
        ):
            builder_type().build_server_verifier(DNSName("cryptography.io"))


class TestCustomPolicyBuilder:
    def test_extension_policy_already_set(self):
        ext_policy = ExtensionPolicy.permit_all()
        with pytest.raises(ValueError):
            CustomPolicyBuilder().ca_extension_policy(
                ext_policy
            ).ca_extension_policy(ext_policy)

        with pytest.raises(ValueError):
            CustomPolicyBuilder().ee_extension_policy(
                ext_policy
            ).ee_extension_policy(ext_policy)

    def test_wrong_extension_policy_type(self):
        with pytest.raises(TypeError):
            CustomPolicyBuilder().ca_extension_policy(
                {"keyUsage": "critical"}  # type: ignore[arg-type]
            )

        with pytest.raises(TypeError):
            CustomPolicyBuilder().ee_extension_policy(
                {"keyUsage": "critical"}  # type: ignore[arg-type]
            )

    def test_eku_bad_type(self):
        with pytest.raises(TypeError):
            CustomPolicyBuilder().eku("not an OID")  # type: ignore[arg-type]

    def test_eku_non_eku_oid(self):
        with pytest.raises(ValueError):
            CustomPolicyBuilder().eku(AuthorityInformationAccessOID.OCSP)

    def test_eku_already_set(self):
        with pytest.raises(ValueError):
            CustomPolicyBuilder().eku(ExtendedKeyUsageOID.IPSEC_IKE).eku(
                ExtendedKeyUsageOID.IPSEC_IKE
            )


class TestStore:
    def test_store_rejects_empty_list(self):
        with pytest.raises(ValueError):
            Store([])

    def test_store_rejects_non_certificates(self):
        with pytest.raises(TypeError):
            Store(["not a cert"])  # type: ignore[list-item]


@pytest.mark.parametrize(
    "builder_type",
    [
        PolicyBuilder,
        CustomPolicyBuilder,
    ],
)
class TestClientVerifier:
    def test_build_client_verifier_missing_store(self, builder_type):
        with pytest.raises(
            ValueError, match="A client verifier must have a trust store"
        ):
            builder_type().build_client_verifier()

    def test_verify(self, builder_type):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2018-11-16T00:00:00+00:00"
        )
        builder = builder_type().store(store)
        builder = builder.time(validation_time).max_chain_depth(16)
        verifier = builder.build_client_verifier()

        assert verifier.validation_time == validation_time.replace(tzinfo=None)
        assert verifier.max_chain_depth == 16
        assert verifier.store is store

        verified_client = verifier.verify(leaf, [])
        assert verified_client.chain == [leaf]

        assert verified_client.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        ) == [
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "www.cryptography.io")
        ]
        assert x509.DNSName("www.cryptography.io") in verified_client.sans
        assert x509.DNSName("cryptography.io") in verified_client.sans

        assert len(verified_client.sans) == 2

    def test_verify_fails_renders_oid(self, builder_type):
        leaf = _load_cert(
            os.path.join("x509", "custom", "ekucrit-testuser-cert.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        validation_time = datetime.datetime.fromisoformat(
            "2024-06-26T00:00:00+00:00"
        )

        builder = builder_type().store(store)
        builder = builder.time(validation_time)
        verifier = builder.build_client_verifier()

        pattern = (
            r"invalid extension: 2\.5\.29\.37: "
            r"Certificate extension has incorrect criticality"
        )
        with pytest.raises(
            VerificationError,
            match=pattern,
        ):
            verifier.verify(leaf, [])


class TestCustomVerify:
    leaf = _load_cert(
        os.path.join("x509", "cryptography.io.pem"),
        x509.load_pem_x509_certificate,
    )
    ca = _load_cert(
        os.path.join("x509", "rapidssl_sha256_ca_g3.pem"),
        x509.load_pem_x509_certificate,
    )
    store = Store([ca])
    validation_time = datetime.datetime.fromisoformat(
        "2018-11-16T00:00:00+00:00"
    )

    @staticmethod
    def _eku_validator_cb(policy, cert, ext):
        assert isinstance(policy, Policy)
        assert (
            policy.validation_time
            == TestCustomVerify.validation_time.replace(tzinfo=None)
        )
        assert isinstance(cert, x509.Certificate)
        assert ext is None or isinstance(ext, x509.ExtendedKeyUsage)

    def test_extension_validator_cb_pass(self):
        ee_extension_policy = ExtensionPolicy.web_pki_defaults_ee()
        ca_extension_policy = ExtensionPolicy.web_pki_defaults_ca()

        eku_validator = ExtensionValidator.maybe_present(
            Criticality.AGNOSTIC, self._eku_validator_cb
        )
        ca_extension_policy.extended_key_usage = eku_validator
        ee_extension_policy.extended_key_usage = eku_validator

        ca_validator_called = False

        def ca_validator(policy, cert, ext):
            assert cert == self.ca
            assert isinstance(policy, Policy)
            assert isinstance(cert, Certificate)
            assert isinstance(ext, x509.BasicConstraints)
            nonlocal ca_validator_called
            ca_validator_called = True

        ca_extension_policy.basic_constraints = (
            ExtensionValidator.maybe_present(
                Criticality.AGNOSTIC, ca_validator
            )
        )

        builder = CustomPolicyBuilder().store(self.store)
        builder = builder.time(self.validation_time).max_chain_depth(16)
        builder = builder.ee_extension_policy(ee_extension_policy)
        builder = builder.ca_extension_policy(ca_extension_policy)

        builder.build_client_verifier().verify(self.leaf, [])
        assert ca_validator_called
        ca_validator_called = False

        path = builder.build_server_verifier(
            DNSName("cryptography.io")
        ).verify(self.leaf, [])
        assert ca_validator_called
        assert path == [self.leaf, self.ca]

    def test_extension_validator_cb_fail(self):
        # TODO
        pass


class TestServerVerifier:
    @pytest.mark.parametrize(
        ("validation_time", "valid"),
        [
            # 03:15:02 UTC+2, or 1 second before expiry in UTC
            ("2018-11-16T03:15:02+02:00", True),
            # 00:15:04 UTC-1, or 1 second after expiry in UTC
            ("2018-11-16T00:15:04-01:00", False),
        ],
    )
    def test_verify_tz_aware(self, validation_time, valid):
        # expires 2018-11-16 01:15:03 UTC
        leaf = _load_cert(
            os.path.join("x509", "cryptography.io.pem"),
            x509.load_pem_x509_certificate,
        )

        store = Store([leaf])

        builder = PolicyBuilder().store(store)
        builder = builder.time(
            datetime.datetime.fromisoformat(validation_time)
        )
        verifier = builder.build_server_verifier(DNSName("cryptography.io"))

        if valid:
            assert verifier.verify(leaf, []) == [leaf]
        else:
            with pytest.raises(
                x509.verification.VerificationError,
                match="cert is not valid at validation time",
            ):
                verifier.verify(leaf, [])
