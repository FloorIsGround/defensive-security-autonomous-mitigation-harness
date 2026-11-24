use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

use defsec_policy::edge_floor::is_valid_identifier;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    version::TLS13,
};
use sha2::{Digest, Sha256};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::extensions::GeneralName;

use crate::{
    MtlsError, Result, RevocationList,
    pki::{HOST_URI_PREFIX, cert_serial, parse_cert},
};

pub type MtlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;
pub type MtlsClientStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, PartialEq, Eq)]
pub struct PeerHostIdentity {
    pub host_id: String,
    pub serial_hex: String,
    pub fingerprint_sha256: String,
}

#[derive(Clone)]
pub struct MtlsAcceptor {
    tls: TlsAcceptor,
    revoked_file: Option<Arc<PathBuf>>,
}

impl MtlsAcceptor {
    pub fn from_pem_files(
        ca_cert: impl AsRef<Path>,
        server_cert: impl AsRef<Path>,
        server_key: impl AsRef<Path>,
        revoked_file: Option<PathBuf>,
    ) -> Result<Self> {
        let provider = Arc::new(default_provider());
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(load_roots(ca_cert.as_ref())?),
            provider.clone(),
        )
        .build()?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                read_certs(&fs::read(server_cert)?)?,
                load_key(server_key.as_ref())?,
            )?;
        // Require certificate authentication on every connection.
        config.send_tls13_tickets = 0;
        Ok(Self {
            tls: TlsAcceptor::from(Arc::new(config)),
            revoked_file: revoked_file.map(Arc::new),
        })
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<(MtlsServerStream, PeerHostIdentity)> {
        let stream = self.tls.accept(stream).await?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(MtlsError::Invalid("missing client certificate"))?;
        let revoked = match self.revoked_file.clone() {
            Some(path) => {
                tokio::task::spawn_blocking(move || RevocationList::load_or_empty(path.as_path()))
                    .await
                    .map_err(io::Error::other)??
            }
            None => RevocationList::default(),
        };
        let identity = peer_identity(leaf, &revoked)?;
        Ok((stream, identity))
    }
}

#[derive(Clone)]
pub struct MtlsConnector(TlsConnector);

impl MtlsConnector {
    pub fn from_pem_files(
        ca_cert: impl AsRef<Path>,
        client_cert: impl AsRef<Path>,
        client_key: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&TLS13])?
            .with_root_certificates(load_roots(ca_cert.as_ref())?)
            .with_client_auth_cert(
                read_certs(&fs::read(client_cert)?)?,
                load_key(client_key.as_ref())?,
            )?;
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self(TlsConnector::from(Arc::new(config))))
    }

    pub async fn connect(
        &self,
        addr: impl ToSocketAddrs,
        server_name: &str,
    ) -> Result<MtlsClientStream> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| MtlsError::Invalid("invalid TLS server name"))?;
        Ok(self
            .0
            .connect(name, TcpStream::connect(addr).await?)
            .await?)
    }
}

fn peer_identity(der: &[u8], revoked: &RevocationList) -> Result<PeerHostIdentity> {
    let cert = parse_cert(der)?;
    let serial_hex = cert_serial(&cert)?;
    if revoked.is_revoked(&serial_hex) {
        return Err(MtlsError::Revoked(serial_hex));
    }
    let san = cert
        .subject_alternative_name()
        .map_err(|_| MtlsError::Invalid("invalid client SAN extension"))?
        .ok_or(MtlsError::Invalid("missing client SAN extension"))?;
    let mut host_id = None;
    let host_path = HOST_URI_PREFIX.trim_end_matches('/');
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name
            && uri
                .get(..host_path.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(host_path))
            && matches!(
                uri.as_bytes().get(host_path.len()),
                None | Some(b'/' | b'?' | b'#')
            )
        {
            let host = uri
                .strip_prefix(HOST_URI_PREFIX)
                .filter(|host| is_valid_identifier(host))
                .ok_or(MtlsError::Invalid("invalid client host URI SAN"))?;
            if host_id.replace(host).is_some() {
                return Err(MtlsError::Invalid("multiple client host URI SANs"));
            }
        }
    }
    Ok(PeerHostIdentity {
        host_id: host_id
            .ok_or(MtlsError::Invalid("missing client host URI SAN"))?
            .into(),
        serial_hex,
        fingerprint_sha256: hex::encode(Sha256::digest(der)),
    })
}

pub(crate) fn read_certs(mut pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut pem).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(MtlsError::Invalid("PEM file has no certificates"));
    }
    Ok(certs)
}

fn load_roots(path: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in read_certs(&fs::read(path)?)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut fs::read(path)?.as_slice())?
        .ok_or(MtlsError::Invalid("PEM file has no private key"))
}

#[cfg(test)]
mod tests;
