use crate::error::{CryptographyError, CryptographyResult};
use crate::x509::common::{datetime_now, py_to_datetime};
use cryptography_x509_verification::policy::Policy;

use super::common::{
    build_subject, build_subject_owner, OwnedPolicy, PyClientVerifier, PyCryptoOps,
    PyCryptoOpsPolicy, PyServerVerifier, PyStore,
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
        if self.time.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The validation time may only be set once.",
                ),
            ));
        }
        Ok(PolicyBuilder {
            time: Some(py_to_datetime(py, new_time)?),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: self.max_chain_depth,
        })
    }

    fn store(&self, new_store: pyo3::Py<PyStore>) -> CryptographyResult<PolicyBuilder> {
        if self.store.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("The trust store may only be set once."),
            ));
        }
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
        if self.max_chain_depth.is_some() {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The maximum chain depth may only be set once.",
                ),
            ));
        }
        Ok(PolicyBuilder {
            time: self.time.clone(),
            store: self.store.as_ref().map(|s| s.clone_ref(py)),
            max_chain_depth: Some(new_max_chain_depth),
        })
    }

    fn build_client_verifier(&self, py: pyo3::Python<'_>) -> CryptographyResult<PyClientVerifier> {
        let store = match self.store.as_ref() {
            Some(s) => s.clone_ref(py),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "A client verifier must have a trust store.",
                    ),
                ));
            }
        };

        let time = match self.time.as_ref() {
            Some(t) => t.clone(),
            None => datetime_now(py)?,
        };

        let policy = Policy::web_pki_client(PyCryptoOps {}, time, self.max_chain_depth);

        Ok(PyClientVerifier { policy, store })
    }

    fn build_server_verifier(
        &self,
        py: pyo3::Python<'_>,
        subject: pyo3::PyObject,
    ) -> CryptographyResult<PyServerVerifier> {
        let store = match self.store.as_ref() {
            Some(s) => s.clone_ref(py),
            None => {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "A server verifier must have a trust store.",
                    ),
                ));
            }
        };

        let time = match self.time.as_ref() {
            Some(t) => t.clone(),
            None => datetime_now(py)?,
        };
        let subject_owner = build_subject_owner(py, &subject)?;

        let policy = OwnedPolicy::try_new(subject_owner, |subject_owner| {
            let subject = build_subject(py, subject_owner)?;
            Ok::<PyCryptoOpsPolicy<'_>, pyo3::PyErr>(Policy::web_pki_server(
                PyCryptoOps {},
                subject,
                time,
                self.max_chain_depth,
            ))
        })?;

        Ok(PyServerVerifier {
            py_subject: subject,
            policy,
            store,
        })
    }
}
