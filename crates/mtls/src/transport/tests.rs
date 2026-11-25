use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use rcgen::{CertificateParams, KeyPair, SanType};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use super::*;
use crate::pki::{CaPem, IssuedCert, init_ca, issue_host_cert, issue_server_cert};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("mtls-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test directory: {e}"),
            }
        }
    }

    fn write(&self, name: &str, pem: &str) -> PathBuf {
        let path = self.0.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, pem.as_bytes()).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ca() -> CaPem {
    init_ca("Fleet test CA", 60).unwrap()
}

fn server(ca: &CaPem) -> IssuedCert {
    issue_server_cert(
        &ca.cert_pem,
        &ca.key_pem,
        "control",
        &["localhost".into()],
        &["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        30,
    )
    .unwrap()
}

fn host(ca: &CaPem) -> IssuedCert {
    issue_host_cert(&ca.cert_pem, &ca.key_pem, "edge-01", 30).unwrap()
}

#[test]
fn issued_certificates_have_distinct_serials_and_role_specific_extensions() {
    let ca = ca();
    let roots = read_certs(ca.cert_pem.as_bytes()).unwrap();
    let issuer = parse_cert(&roots[0]).unwrap();
    assert!(issuer.is_ca());
    assert!(issuer.key_usage().unwrap().unwrap().value.key_cert_sign());
    let server = server(&ca);
    let host = host(&ca);
    assert_ne!(server.serial_hex, host.serial_hex);
    for (issued, common_name, is_server) in [(&server, "control", true), (&host, "edge-01", false)]
    {
        let leaf = read_certs(issued.cert_pem.as_bytes()).unwrap();
        let cert = parse_cert(&leaf[0]).unwrap();
        assert!(!cert.is_ca());
        assert_eq!(cert.issuer(), issuer.subject());
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            common_name
        );
        assert_eq!(cert_serial(&cert).unwrap(), issued.serial_hex);
        let usage = cert.extended_key_usage().unwrap().unwrap().value;
        assert_eq!(usage.server_auth, is_server);
        assert_ne!(usage.client_auth, is_server);
        let san = &cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names;
        if is_server {
            assert_eq!(
                san,
                &[
                    GeneralName::DNSName("localhost"),
                    GeneralName::IPAddress(&[127, 0, 0, 1]),
                    GeneralName::IPAddress(&std::net::Ipv6Addr::LOCALHOST.octets()),
                ]
            );
            assert!(peer_identity(&leaf[0], &RevocationList::default()).is_err());
        } else {
            assert_eq!(
                san,
                &[GeneralName::URI("spiffe://defsecautmit/host/edge-01")]
            );
            let identity = peer_identity(&leaf[0], &RevocationList::default()).unwrap();
            assert_eq!(identity.host_id, "edge-01");
            assert_eq!(identity.serial_hex, host.serial_hex);
            assert_eq!(
                identity.fingerprint_sha256,
                hex::encode(Sha256::digest(&leaf[0]))
            );
        }
    }
}

#[test]
fn invalid_issuance_inputs_are_rejected() {
    let root = ca();
    let other = ca();
    assert!(init_ca("root", 0).is_err());
    assert!(init_ca("root", u64::MAX).is_err());
    assert!(issue_host_cert(&root.cert_pem, &other.key_pem, "edge-01", 30).is_err());
    assert!(issue_host_cert(&root.cert_pem, &root.key_pem, "../edge-01", 30).is_err());
    assert!(issue_host_cert(&root.cert_pem, &root.key_pem, "edge-01", 61).is_err());
    assert!(issue_server_cert(&root.cert_pem, &root.key_pem, "control", &[], &[], 30).is_err());
}

#[test]
fn missing_malformed_and_multiple_host_uris_are_rejected() {
    for uris in [
        vec![],
        vec!["spiffe://foreign/host/edge-01"],
        vec!["spiffe://defsecautmit/host/"],
        vec!["spiffe://defsecautmit/host/edge-01/edge-02"],
        vec!["spiffe://defsecautmit/host/edge%2D01"],
        vec!["spiffe://defsecautmit/host/edge-01?query"],
        vec![
            "spiffe://defsecautmit/host/edge-01",
            "spiffe://defsecautmit/host/edge-02",
        ],
        vec![
            "spiffe://defsecautmit/host/edge-01",
            "SPIFFE://defsecautmit/host/edge-01",
        ],
        vec![
            "spiffe://defsecautmit/host/edge-01",
            "spiffe://defsecautmit/host",
        ],
    ] {
        let mut params = CertificateParams::default();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI((*uri).try_into().unwrap()))
            .collect();
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert!(
            peer_identity(cert.der(), &RevocationList::default()).is_err(),
            "{uris:?}"
        );
    }
}

#[test]
fn revocation_normalizes_serials_and_preserves_concurrent_updates() {
    let dir = TempDir::new();
    let path = dir.0.join("revoked.json");
    assert!(
        !RevocationList::load_or_empty(&path)
            .unwrap()
            .is_revoked("ab")
    );
    assert_eq!(
        RevocationList::revoke(&path, "000AB", Some("rotated")).unwrap(),
        "ab"
    );
    let before = fs::read(&path).unwrap();
    RevocationList::revoke(&path, "aB", Some("duplicate")).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(RevocationList::revoke(&path, "invalid", None).is_err());
    std::thread::scope(|scope| {
        for serial in ["12", "34", "56", "78"] {
            let path = &path;
            scope.spawn(move || RevocationList::revoke(path, serial, None).unwrap());
        }
    });
    let list = RevocationList::load_or_empty(&path).unwrap();
    for serial in ["Ab", "000ab", "12", "34", "56", "78"] {
        assert!(list.is_revoked(serial));
    }
    assert!(!list.is_revoked("90"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::write(&path, b"broken JSON").unwrap();
    assert!(RevocationList::load_or_empty(&path).is_err());
    assert!(RevocationList::revoke(&path, "90", None).is_err());
}

fn acceptor(dir: &TempDir, ca: &CaPem, ca_path: &Path) -> MtlsAcceptor {
    let server = server(ca);
    MtlsAcceptor::from_pem_files(
        ca_path,
        dir.write("server.crt", &server.cert_pem),
        dir.write("server.key", &server.key_pem),
        Some(dir.0.join("revoked.json")),
    )
    .unwrap()
}

fn connector(dir: &TempDir, ca_path: &Path, host: &IssuedCert) -> MtlsConnector {
    MtlsConnector::from_pem_files(
        ca_path,
        dir.write("client.crt", &host.cert_pem),
        dir.write("client.key", &host.key_pem),
    )
    .unwrap()
}

#[tokio::test]
async fn mutual_tls_13_round_trip() {
    let dir = TempDir::new();
    let ca = ca();
    let ca_path = dir.write("ca.crt", &ca.cert_pem);
    let host = host(&ca);
    let acceptor = acceptor(&dir, &ca, &ca_path);
    let connector = connector(&dir, &ca_path, &host);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut tls, identity) = acceptor.accept(stream).await.unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(identity.host_id, "edge-01");
        assert_eq!(identity.serial_hex, host.serial_hex);
        let mut bytes = [0; 4];
        tls.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        tls.write_all(b"pong").await.unwrap();
        tls.flush().await.unwrap();
    };
    let client = async {
        let mut tls = connector.connect(addr, "127.0.0.1").await.unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut bytes = [0; 4];
        tls.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"pong");
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn untrusted_client_ca_is_rejected_in_handshake() {
    let dir = TempDir::new();
    let trusted = ca();
    let ca_path = dir.write("ca.crt", &trusted.cert_pem);
    let acceptor = acceptor(&dir, &trusted, &ca_path);
    let connector = connector(&dir, &ca_path, &host(&ca()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(acceptor.accept(stream).await, Err(MtlsError::Io(e)) if e.kind() == io::ErrorKind::InvalidData)
        );
    };
    let client = async {
        if let Ok(mut stream) = connector.connect(addr, "localhost").await {
            assert!(stream.read_u8().await.is_err());
        }
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_requires_a_client_cert_and_tls_13() {
    let dir = TempDir::new();
    let ca = ca();
    let ca_path = dir.write("ca.crt", &ca.cert_pem);
    let acceptor = acceptor(&dir, &ca, &ca_path);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    for version in [&TLS13, &rustls::version::TLS12] {
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(load_roots(&ca_path).unwrap())
            .with_no_client_auth();
        let connector = MtlsConnector(TlsConnector::from(Arc::new(config)));
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let Err(MtlsError::Io(error)) = acceptor.accept(stream).await else {
                panic!("server must reject the handshake");
            };
            let cause = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<rustls::Error>());
            if version.version == rustls::ProtocolVersion::TLSv1_3 {
                assert!(matches!(
                    cause,
                    Some(rustls::Error::NoCertificatesPresented)
                ));
            } else {
                assert!(matches!(cause, Some(rustls::Error::PeerIncompatible(_))));
            }
        };
        let client = async {
            if let Ok(mut stream) = connector.connect(addr, "localhost").await {
                assert!(stream.read_u8().await.is_err());
            }
        };
        timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap();
    }
}
