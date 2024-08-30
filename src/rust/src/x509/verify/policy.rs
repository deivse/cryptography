use std::net::IpAddr;
use std::sync::Arc;

use cryptography_x509::{certificate::Certificate, extensions::Extension};

use cryptography_x509_verification::policy::{
    Criticality, ExtensionPolicy, ExtensionValidator, MaybeExtensionValidatorCallback, Policy,
    PresentExtensionValidatorCallback, Subject,
};
use cryptography_x509_verification::ValidationError;
use pyo3::types::PyAnyMethods;
use pyo3::PyTypeInfo;

use crate::asn1::oid_to_py_oid;

use crate::error::{CryptographyError, CryptographyResult};
use crate::types;
use crate::x509::certificate::Certificate as PyCertificate;
use crate::x509::certificate::{parse_cert_ext, OwnedCertificate};
use crate::x509::datetime_to_py;

use super::common::PyCryptoOps;

#[pyo3::pyclass(
    frozen,
    eq,
    module = "cryptography.x509.verification",
    name = "Criticality"
)]
#[derive(PartialEq, Eq, Clone)]
pub(crate) enum PyCriticality {
    #[pyo3(name = "CRITICAL")]
    Critical,
    #[pyo3(name = "AGNOSTIC")]
    Agnostic,
    #[pyo3(name = "NON_CRITICAL")]
    NonCritical,
}

impl From<PyCriticality> for Criticality {
    fn from(criticality: PyCriticality) -> Criticality {
        match criticality {
            PyCriticality::Critical => Criticality::Critical,
            PyCriticality::Agnostic => Criticality::Agnostic,
            PyCriticality::NonCritical => Criticality::NonCritical,
        }
    }
}

impl From<Criticality> for PyCriticality {
    fn from(criticality: Criticality) -> PyCriticality {
        match criticality {
            Criticality::Critical => PyCriticality::Critical,
            Criticality::Agnostic => PyCriticality::Agnostic,
            Criticality::NonCritical => PyCriticality::NonCritical,
        }
    }
}

// TODO: can I make these a single rust enum?..
#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "ExtensionValidatorNotPresent"
)]
pub(crate) struct PyExtensionValidatorNotPresent {}

#[pyo3::pymethods]
impl PyExtensionValidatorNotPresent {
    #[new]
    fn new() -> PyExtensionValidatorNotPresent {
        PyExtensionValidatorNotPresent {}
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "ExtensionValidatorMaybePresent"
)]
pub(crate) struct PyExtensionValidatorMaybePresent {
    criticality: PyCriticality,
    validator: Option<pyo3::PyObject>,
}

#[pyo3::pymethods]
impl PyExtensionValidatorMaybePresent {
    #[new]
    #[pyo3(signature = (criticality, validator))]
    fn new(
        criticality: PyCriticality,
        validator: Option<pyo3::PyObject>,
    ) -> PyExtensionValidatorMaybePresent {
        PyExtensionValidatorMaybePresent {
            criticality,
            validator,
        }
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "ExtensionValidatorPresent"
)]
pub(crate) struct PyExtensionValidatorPresent {
    criticality: PyCriticality,
    validator: Option<pyo3::PyObject>,
}

#[pyo3::pymethods]
impl PyExtensionValidatorPresent {
    #[new]
    #[pyo3(signature = (criticality, validator))]
    fn new(
        criticality: PyCriticality,
        validator: Option<pyo3::PyObject>,
    ) -> PyExtensionValidatorPresent {
        PyExtensionValidatorPresent {
            criticality,
            validator,
        }
    }
}

fn cert_to_py_cert(
    py: pyo3::Python<'_>,
    cert: &Certificate<'_>,
) -> CryptographyResult<PyCertificate> {
    // TODO: can this be done better?..
    let data = asn1::write_single(cert)?;
    let owned_cert = OwnedCertificate::try_new(
        pyo3::types::PyBytes::new_bound(py, data.as_slice())
            .as_unbound()
            .clone_ref(py),
        |bytes| asn1::parse_single(bytes.as_bytes(py)),
    )?;
    Ok(PyCertificate {
        raw: owned_cert,
        cached_extensions: pyo3::sync::GILOnceCell::new(),
    })
}

fn make_python_callback_args<'p>(
    py: pyo3::Python<'p>,
    policy: &Policy<'_, PyCryptoOps>,
    cert: &Certificate<'_>,
    ext: Option<&Extension<'_>>,
) -> Result<
    (
        PyPolicy,
        PyCertificate,
        Option<pyo3::Bound<'p, pyo3::types::PyAny>>,
    ),
    ValidationError,
> {
    let py_policy = PyPolicy::from_rust_policy(py, policy).map_err(|e| {
        ValidationError::Other(format!("{e} (while converting to python policy object)"))
    })?;
    let py_cert = cert_to_py_cert(py, cert).map_err(|e| {
        ValidationError::Other(format!(
            "{e} (while converting to python certificate object)"
        ))
    })?;
    let py_ext = match ext {
        None => None,
        Some(ext) => parse_cert_ext(py, ext).map_err(|e| {
            ValidationError::Other(format!(
                "{} (while converting to python extension object)",
                Into::<pyo3::PyErr>::into(e)
            ))
        })?,
    };

    Ok((py_policy, py_cert, py_ext))
}

fn invoke_py_validator_callback(
    py: pyo3::Python<'_>,
    py_cb: &pyo3::PyObject,
    args: impl pyo3::IntoPy<pyo3::Py<pyo3::types::PyTuple>>,
) -> Result<(), ValidationError> {
    let result = py_cb
        .bind(py)
        .call1(args)
        .map_err(|e| ValidationError::Other(format!("Python validator failed: {}", e)))?;

    if !result.is_none() {
        Err(ValidationError::Other(
            "Python validator must return None.".to_string(),
        ))
    } else {
        Ok(())
    }
}

impl<'a> PyExtensionValidatorMaybePresent {
    fn make_rust_extension_validator(
        &self,
        py: pyo3::Python<'_>,
    ) -> ExtensionValidator<'a, PyCryptoOps> {
        fn make_rust_maybe_validator<'a>(
            py_cb: pyo3::PyObject,
        ) -> MaybeExtensionValidatorCallback<'a, PyCryptoOps> {
            Arc::new(
                move |policy: &Policy<'_, PyCryptoOps>,
                      cert: &Certificate<'_>,
                      ext: Option<&Extension<'_>>|
                      -> Result<(), ValidationError> {
                    pyo3::Python::with_gil(|py| -> Result<(), ValidationError> {
                        let args = make_python_callback_args(py, policy, cert, ext)?;
                        invoke_py_validator_callback(py, &py_cb, args)
                    })
                },
            )
        }
        ExtensionValidator::MaybePresent {
            criticality: self.criticality.clone().into(),
            validator: match &self.validator {
                None => None,
                Some(py_cb) => Some(make_rust_maybe_validator(py_cb.clone_ref(py))),
            },
        }
    }
}

impl<'a> PyExtensionValidatorPresent {
    fn make_rust_extension_validator(
        &self,
        py: pyo3::Python<'_>,
    ) -> ExtensionValidator<'a, PyCryptoOps> {
        fn make_rust_present_validator<'a>(
            py_cb: pyo3::PyObject,
        ) -> PresentExtensionValidatorCallback<'a, PyCryptoOps> {
            Arc::new(
                move |policy: &Policy<'_, PyCryptoOps>,
                      cert: &Certificate<'_>,
                      ext: &Extension<'_>|
                      -> Result<(), ValidationError> {
                    pyo3::Python::with_gil(|py| -> Result<(), ValidationError> {
                        let args = make_python_callback_args(py, policy, cert, Some(ext))?;
                        let args = (args.0, args.1, args.2.unwrap());

                        invoke_py_validator_callback(py, &py_cb, args)
                    })
                },
            )
        }

        ExtensionValidator::Present {
            criticality: self.criticality.clone().into(),
            validator: match &self.validator {
                None => None,
                Some(py_cb) => Some(make_rust_present_validator(py_cb.clone_ref(py))),
            },
        }
    }
}

#[pyo3::pyclass(module = "cryptography.x509.verification", name = "ExtensionPolicy")]
pub(crate) struct PyExtensionPolicy {
    #[pyo3(get, set)]
    authority_information_access: pyo3::PyObject,
    #[pyo3(get, set)]
    authority_key_identifier: pyo3::PyObject,
    #[pyo3(get, set)]
    subject_key_identifier: pyo3::PyObject,
    #[pyo3(get, set)]
    key_usage: pyo3::PyObject,
    #[pyo3(get, set)]
    subject_alternative_name: pyo3::PyObject,
    #[pyo3(get, set)]
    basic_constraints: pyo3::PyObject,
    #[pyo3(get, set)]
    name_constraints: pyo3::PyObject,
    #[pyo3(get, set)]
    extended_key_usage: pyo3::PyObject,
}

#[pyo3::pymethods]
impl PyExtensionPolicy {
    #[staticmethod]
    pub(crate) fn permit_all(py: pyo3::Python<'_>) -> Self {
        PyExtensionPolicy::from_rust_extension_policy(py, &ExtensionPolicy::new_permit_all())
    }

    #[staticmethod]
    pub(crate) fn web_pki_defaults_ca(py: pyo3::Python<'_>) -> Self {
        PyExtensionPolicy::from_rust_extension_policy(
            py,
            &ExtensionPolicy::new_default_web_pki_ca(),
        )
    }

    #[staticmethod]
    pub(crate) fn web_pki_defaults_ee(py: pyo3::Python<'_>) -> Self {
        PyExtensionPolicy::from_rust_extension_policy(
            py,
            &ExtensionPolicy::new_default_web_pki_ee(),
        )
    }
}

#[pyo3::pyclass(
    frozen,
    module = "cryptography.x509.verification",
    name = "OpaqueExtensionValidator"
)]
/// Used to store default rust extension validators in PyExtensionPolicy.
struct PyOpaqueExtensionValidator(ExtensionValidator<'static, PyCryptoOps>);

impl PyExtensionPolicy {
    pub(super) fn from_rust_extension_policy(
        py: pyo3::Python<'_>,
        policy: &ExtensionPolicy<'static, PyCryptoOps>,
    ) -> PyExtensionPolicy {
        let to_py_validator = |validator: &ExtensionValidator<'static, PyCryptoOps>| {
            pyo3::IntoPy::into_py(PyOpaqueExtensionValidator(validator.clone()), py)
        };

        PyExtensionPolicy {
            authority_information_access: to_py_validator(&policy.authority_information_access),
            authority_key_identifier: to_py_validator(&policy.authority_key_identifier),
            subject_key_identifier: to_py_validator(&policy.subject_key_identifier),
            key_usage: to_py_validator(&policy.key_usage),
            subject_alternative_name: to_py_validator(&policy.subject_alternative_name),
            basic_constraints: to_py_validator(&policy.basic_constraints),
            name_constraints: to_py_validator(&policy.name_constraints),
            extended_key_usage: to_py_validator(&policy.extended_key_usage),
        }
    }

    pub(super) fn to_rust_extension_policy(
        &self,
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<ExtensionPolicy<'static, PyCryptoOps>> {
        let to_rust_validator = |field: &pyo3::PyObject| {
            let py_validator = field.bind(py);

            let wrapped_validator = if PyOpaqueExtensionValidator::is_type_of_bound(py_validator) {
                py_validator
                    .downcast::<PyOpaqueExtensionValidator>()
                    .unwrap()
                    .get()
                    .0
                    .clone()
            } else if PyExtensionValidatorNotPresent::is_type_of_bound(py_validator) {
                ExtensionValidator::NotPresent
            } else if PyExtensionValidatorMaybePresent::is_type_of_bound(py_validator) {
                py_validator
                    .downcast::<PyExtensionValidatorMaybePresent>()
                    .unwrap()
                    .get()
                    .make_rust_extension_validator(py)
            } else if PyExtensionValidatorPresent::is_type_of_bound(py_validator) {
                py_validator
                    .downcast::<PyExtensionValidatorPresent>()
                    .unwrap()
                    .get()
                    .make_rust_extension_validator(py)
            } else {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyTypeError::new_err("Invalid extension validator type"),
                ));
            };

            Ok(wrapped_validator)
        };

        Ok(ExtensionPolicy {
            authority_information_access: to_rust_validator(&self.authority_information_access)?,
            authority_key_identifier: to_rust_validator(&self.authority_key_identifier)?,
            subject_key_identifier: to_rust_validator(&self.subject_key_identifier)?,
            key_usage: to_rust_validator(&self.key_usage)?,
            subject_alternative_name: to_rust_validator(&self.subject_alternative_name)?,
            basic_constraints: to_rust_validator(&self.basic_constraints)?,
            name_constraints: to_rust_validator(&self.name_constraints)?,
            extended_key_usage: to_rust_validator(&self.extended_key_usage)?,
        })
    }
}

#[pyo3::pyclass(module = "cryptography.x509.verification", name = "Policy")]
pub(crate) struct PyPolicy {
    #[pyo3(get)]
    max_chain_depth: u8,
    #[pyo3(get)]
    subject: Option<pyo3::PyObject>,
    #[pyo3(get)]
    validation_time: pyo3::PyObject,
    #[pyo3(get)]
    extended_key_usage: Option<pyo3::PyObject>,
    #[pyo3(get)]
    minimum_rsa_modulus: usize,
}

impl PyPolicy {
    fn from_rust_policy(
        py: pyo3::Python<'_>,
        policy: &Policy<'_, PyCryptoOps>,
    ) -> pyo3::PyResult<PyPolicy> {
        let subject = if let Some(subject) = &policy.subject {
            Some(
                match subject {
                    Subject::DNS(dns_name) => {
                        types::DNS_NAME.get(py)?.call1((dns_name.as_str(),))?
                    }
                    Subject::IP(ip_address) => {
                        let ip_string = Into::<IpAddr>::into(*ip_address).to_string();
                        let py_ip_address =
                            types::IPADDRESS_IPADDRESS.get(py)?.call1((ip_string,))?;
                        types::IP_ADDRESS.get(py)?.call1((py_ip_address,))?
                    }
                }
                .as_unbound()
                .clone_ref(py),
            )
        } else {
            None
        };

        let extended_key_usage = if let Some(eku) = &policy.extended_key_usage {
            Some(oid_to_py_oid(py, eku)?.as_unbound().clone_ref(py))
        } else {
            None
        };

        Ok(PyPolicy {
            max_chain_depth: policy.max_chain_depth,
            subject,
            validation_time: datetime_to_py(py, &policy.validation_time)?
                .as_unbound()
                .clone_ref(py),
            extended_key_usage,
            minimum_rsa_modulus: policy.minimum_rsa_modulus,
        })
    }
}
