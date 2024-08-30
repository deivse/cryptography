use cryptography_x509_verification::policy::{ExtensionPolicy, Policy};

use crate::asn1::py_oid_to_oid;
use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::py_to_datetime;

use super::common::{PyClientVerifier, PyCryptoOps, PyServerVerifier, PyStore};
use super::policy::PyExtensionPolicy;

#[pyo3::pyclass(frozen, module = "cryptography.x509.verification")]
pub(crate) struct CustomPolicyBuilder {
    time: Option<asn1::DateTime>,
    store: Option<pyo3::Py<PyStore>>,
    max_chain_depth: Option<u8>,
    eku: Option<asn1::ObjectIdentifier>,
    ca_ext_policy: ExtensionPolicy<'static, PyCryptoOps>,
    ee_ext_policy: ExtensionPolicy<'static, PyCryptoOps>,
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
            ca_ext_policy: ExtensionPolicy::new_default_web_pki_ca(),
            ee_ext_policy: ExtensionPolicy::new_default_web_pki_ee(),
        }
    }

    fn time(
        &self,
        py: pyo3::Python<'_>,
        new_time: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        if self.time.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The validation time may only be set once.",
                ),
            ));
        }
        Ok(CustomPolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        })
    }

    fn store(&self, new_store: pyo3::Py<PyStore>) -> CryptographyResult<CustomPolicyBuilder> {
        if self.store.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("The trust store may only be set once."),
            ));
        }
        Ok(CustomPolicyBuilder {
            time: self.time.clone(),
            store: Some(new_store),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        })
    }

    fn max_chain_depth(
        &self,
        py: pyo3::Python<'_>,
        new_max_chain_depth: u8,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        if self.max_chain_depth.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The maximum chain depth may only be set once.",
                ),
            ));
        }
        Ok(CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: Some(new_max_chain_depth),
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        })
    }

    fn eku(
        &self,
        py: pyo3::Python<'_>,
        new_eku: pyo3::Bound<'_, pyo3::PyAny>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        if self.eku.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("The EKUs may only be set once."),
            ));
        }

        let oid = py_oid_to_oid(new_eku)?;
        Ok(CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: Some(oid),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: self.ee_ext_policy.clone(),
        })
    }

    fn ca_extension_policy(
        &self,
        py: pyo3::Python<'_>,
        new_policy: &pyo3::Bound<'_, PyExtensionPolicy>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        let new_policy = new_policy.borrow().to_rust_extension_policy(py)?;
        Ok(CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: new_policy,
            ee_ext_policy: self.ee_ext_policy.clone(),
        })
    }

    fn ee_extension_policy(
        &self,
        py: pyo3::Python<'_>,
        new_policy: &pyo3::Bound<'_, PyExtensionPolicy>,
    ) -> CryptographyResult<CustomPolicyBuilder> {
        let new_policy = new_policy.borrow().to_rust_extension_policy(py)?;
        Ok(CustomPolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
            eku: self.eku.clone(),
            ca_ext_policy: self.ca_ext_policy.clone(),
            ee_ext_policy: new_policy,
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        PyClientVerifier::new(py, &self.store, &self.time, |time| {
            Policy::custom(
                PyCryptoOps {},
                None,
                time,
                self.max_chain_depth,
                self.eku.clone(),
                self.ca_ext_policy.clone(),
                self.ee_ext_policy.clone(),
            )
        })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        PyServerVerifier::new(py, &self.store, &self.time, subject, |subject, time| {
            Policy::custom(
                PyCryptoOps {},
                Some(subject),
                time,
                self.max_chain_depth,
                self.eku.clone(),
                self.ca_ext_policy.clone(),
                self.ee_ext_policy.clone(),
            )
        })
    }
}
