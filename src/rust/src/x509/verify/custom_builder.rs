// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::oid::ALL_EKU_OIDS;
use cryptography_x509_verification::policy::{ExtensionPolicy, Policy};

use crate::asn1::py_oid_to_oid;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::py_to_datetime;
use crate::x509::verify::common::policy_builder_set_once_check;

use super::common::{
    build_client_verifier_impl, build_server_verifier_impl, PyClientVerifier, PyCryptoOps,
    PyServerVerifier, PyStore,
};

#[pyo3::pyclass(frozen, module = "cryptography.x509.verification")]
pub(crate) struct CustomPolicyBuilder {
    time: Option<asn1::DateTime>,
    store: Option<pyo3::Py<PyStore>>,
    max_chain_depth: Option<u8>,
    eku: Option<asn1::ObjectIdentifier>,
    ca_ext_policy: Option<ExtensionPolicy<PyCryptoOps>>,
    ee_ext_policy: Option<ExtensionPolicy<PyCryptoOps>>,
}

impl CustomPolicyBuilder {
    /// Clones the builder, requires the GIL token to increase
    /// reference count for `self.store`.
    fn py_clone(&self, py: pyo3::Python<'_>) -> CustomPolicyBuilder {
        CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        }
    }
}

#[pyo3::pymethods]
impl CustomPolicyBuilder {
    #[new]
    fn new() -> CustomPolicyBuilder {
        CustomPolicyBuilder {
            time: None,
            store: None,
            max_chain_depth: None,
            eku: None,
            ca_ext_policy: None,
            ee_ext_policy: None,
        }
    }

    fn time(
        &self,
        py: pyo3::Python<'_>,
        new_time: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, time, "validation time");

        Ok(CustomPolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            ..self.py_clone(py)
        })
    }

    fn store(
        &self,
        py: pyo3::Python<'_>,
        new_store: pyo3::Py<PyStore>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, store, "trust store");

        Ok(CustomPolicyBuilder {
            store: Some(new_store),
            ..self.py_clone(py)
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, max_chain_depth, "maximum chain depth");

        Ok(CustomPolicyBuilder {
            max_chain_depth: Some(new_max_chain_depth),
            ..self.py_clone(py)
        })
    }

    fn eku(
        &self,
        py: pyo3::Python<'_>,
        new_eku: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        policy_builder_set_once_check!(self, eku, "EKU");

        let oid = py_oid_to_oid(new_eku)?;

        if !ALL_EKU_OIDS.contains(&oid) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "Unknown EKU OID. Only EKUs from x509.ExtendedKeyUsageOID are supported.",
                ),
            ));
        }

        Ok(CustomPolicyBuilder {
            eku: Some(oid),
            ..self.py_clone(py)
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        build_client_verifier_impl(py, &self.store, &self.time, |time| {
            // TODO: Replace with a custom policy once it's implemented in cryptography-x509-verification
            Policy::client(PyCryptoOps {}, time, self.max_chain_depth)
        })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        build_server_verifier_impl(py, &self.store, &self.time, subject, |subject, time| {
            // TODO: Replace with a custom policy once it's implemented in cryptography-x509-verification
            Policy::server(PyCryptoOps {}, subject, time, self.max_chain_depth)
        })
    }
}
