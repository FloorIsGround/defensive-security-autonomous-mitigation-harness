use std::net::IpAddr;

use chrono::{Datelike, TimeDelta, Utc};
use defsec_policy::edge_floor::is_valid_identifier;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, time::ASN1Time};

use crate::{MtlsError, Result, revocation::normalize_serial, transport::read_certs};

pub const HOST_URI_PREFIX: &str = "spiffe://defsecautmit/host/";

pub struct CaPem {
    pub cert_pem: String,
    pub key_pem: String,
}

pub struct IssuedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub serial_hex: String,
}

pub fn init_ca(common_name: &str, valid_days: u64) -> Result<CaPem> {
    let mut params = certificate_params(common_name, valid_days)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    Ok(CaPem {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

pub fn issue_server_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    common_name: &str,
    dns_names: &[String],
    ip_addrs: &[IpAddr],
    valid_days: u64,
) -> Result<IssuedCert> {
    if dns_names.is_empty() && ip_addrs.is_empty() {
        return Err(MtlsError::Invalid(
            "server certificate requires a DNS or IP SAN",
        ));
    }
    let mut params = certificate_params(common_name, valid_days)?;
    for dns in dns_names {
        if !matches!(
            rustls::pki_types::ServerName::try_from(dns.as_str()),
            Ok(rustls::pki_types::ServerName::DnsName(_))
        ) {
            return Err(MtlsError::Invalid("invalid server DNS SAN"));
        }
        params
            .subject_alt_names
            .push(SanType::DnsName(dns.as_str().try_into()?));
    }
    params
        .subject_alt_names
        .extend(ip_addrs.iter().copied().map(SanType::IpAddress));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    issue_cert(ca_cert_pem, ca_key_pem, params)
}

pub fn issue_host_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    host_id: &str,
    valid_days: u64,
) -> Result<IssuedCert> {
    if !is_valid_identifier(host_id) {
        return Err(MtlsError::Invalid("invalid host ID"));
    }
    let mut params = certificate_params(host_id, valid_days)?;
    params.subject_alt_names = vec![SanType::URI(
        format!("{HOST_URI_PREFIX}{host_id}").try_into()?,
    )];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    issue_cert(ca_cert_pem, ca_key_pem, params)
}

fn certificate_params(common_name: &str, valid_days: u64) -> Result<CertificateParams> {
    if common_name.trim().is_empty() {
        return Err(MtlsError::Invalid("certificate common name is empty"));
    }
    let now = Utc::now();
    let expiry = i64::try_from(valid_days)
        .ok()
        .filter(|days| *days > 0)
        .and_then(TimeDelta::try_days)
        .and_then(|validity| now.checked_add_signed(validity))
        .filter(|expiry| expiry.year() <= 9999)
        .ok_or(MtlsError::Invalid("invalid certificate validity in days"))?;
    let asn1 = |timestamp| {
        ASN1Time::from_timestamp(timestamp)
            .map(|time| time.to_datetime())
            .map_err(|_| MtlsError::Invalid("invalid certificate validity timestamp"))
    };
    let mut params = CertificateParams::default();
    params.not_before = asn1((now - TimeDelta::minutes(5)).timestamp())?;
    params.not_after = asn1(expiry.timestamp())?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    Ok(params)
}

fn issue_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    mut params: CertificateParams,
) -> Result<IssuedCert> {
    let ca_certs = read_certs(ca_cert_pem.as_bytes())?;
    let [ca_der] = ca_certs.as_slice() else {
        return Err(MtlsError::Invalid("expected one issuing CA certificate"));
    };
    let ca = parse_cert(ca_der)?;
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    if !ca.is_ca() || ca.public_key().raw != ca_key.public_key_der() {
        return Err(MtlsError::Invalid(
            "issuing CA certificate and key must match",
        ));
    }
    if ca
        .key_usage()
        .map_err(|_| MtlsError::Invalid("invalid CA key usage"))?
        .is_some_and(|usage| !usage.value.key_cert_sign())
    {
        return Err(MtlsError::Invalid(
            "CA key usage forbids certificate signing",
        ));
    }
    if !ca.validity().is_valid() || params.not_after > ca.validity().not_after.to_datetime() {
        return Err(MtlsError::Invalid(
            "certificate validity exceeds issuing CA validity",
        ));
    }
    params.not_before = params
        .not_before
        .max(ca.validity().not_before.to_datetime());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let issuer = CertificateParams::from_ca_cert_der(ca_der)?.self_signed(&ca_key)?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.signed_by(&key, &issuer, &ca_key)?;
    Ok(IssuedCert {
        serial_hex: cert_serial(&parse_cert(cert.der())?)?,
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

pub(crate) fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>> {
    match parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(MtlsError::Invalid("invalid X.509 certificate")),
    }
}

pub(crate) fn cert_serial(cert: &X509Certificate<'_>) -> Result<String> {
    normalize_serial(&hex::encode(cert.raw_serial()))
}
