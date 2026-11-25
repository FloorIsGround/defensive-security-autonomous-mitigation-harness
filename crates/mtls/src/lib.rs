//! Fleet TLS transport and local certificate issuance and revocation.

use std::io;

pub mod pki;
mod revocation;
mod transport;

pub use revocation::RevocationList;
pub use transport::{
    MtlsAcceptor, MtlsClientStream, MtlsConnector, MtlsServerStream, PeerHostIdentity,
};

#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Pki(#[from] rcgen::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Verifier(#[from] rustls::server::VerifierBuilderError),
    #[error("invalid revocation file: {0}")]
    RevocationJson(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("client certificate serial {0} is revoked")]
    Revoked(String),
}

type Result<T> = std::result::Result<T, MtlsError>;
