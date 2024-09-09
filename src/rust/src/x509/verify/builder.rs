// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509_verification::policy::Policy;

use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::py_to_datetime;
use crate::x509::verify::common::policy_builder_set_once_check;

use super::common::{
    build_client_verifier_impl, build_server_verifier_impl, PyClientVerifier, PyCryptoOps,
    PyServerVerifier, PyStore,
};

#[pyo3::pyclass(frozen, module = "cryptography.x509.verification")]
pub(crate) struct PolicyBuilder {
    time: Option<asn1::DateTime>,
    store: Option<pyo3::Py<PyStore>>,
    max_chain_depth: Option<u8>,
}

#[pyo3::pymethods]
impl PolicyBuilder {
    #[new]
    fn new() -> PolicyBuilder {
        PolicyBuilder {
            time: None,
            store: None,
            max_chain_depth: None,
        }
    }

    fn time(
        &self,
        py: pyo3::Python<'_>,
        new_time: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, time, "validation time");

        Ok(PolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
        })
    }

    fn store(&self, new_store: pyo3::Py<PyStore>) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, store, "trust store");

        Ok(PolicyBuilder {
            time: self.time.clone(),
            store: Some(new_store),
            max_chain_depth: self.max_chain_depth,
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<PolicyBuilder> {
        policy_builder_set_once_check!(self, max_chain_depth, "maximum chain depth");

        Ok(PolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: Some(new_max_chain_depth),
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        build_client_verifier_impl(py, &self.store, &self.time, |time| {
            Policy::client(PyCryptoOps {}, time, self.max_chain_depth)
        })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        build_server_verifier_impl(py, &self.store, &self.time, subject, |subject, time| {
            Policy::server(PyCryptoOps {}, subject, time, self.max_chain_depth)
        })
    }
}
