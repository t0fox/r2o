//! Проверка доступности Meta edge без передачи заблокированного SNI.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const NEUTRAL_SNI: &str = "example.com";

pub const META_HOSTS: &[&str] = &[
    "instagram.com",
    "www.instagram.com",
    "graph.instagram.com",
    "api.instagram.com",
    "i.instagram.com",
    "instagram.c10r.instagram.com",
    "static.cdninstagram.com",
    "scontent.cdninstagram.com",
    "static.xx.fbcdn.net",
    "scontent.xx.fbcdn.net",
    "web.whatsapp.com",
    "www.whatsapp.com",
    "scontent.whatsapp.net",
    "graph.whatsapp.com",
    "v.whatsapp.com",
    "static.whatsapp.net",
    "mmg.whatsapp.net",
    "pps.whatsapp.net",
];

/// Возвращает имя, которому должен соответствовать сертификат.
/// `instagram.c10r.instagram.com` — единственный alias с отдельным именем.
pub fn certificate_name(host: &str) -> Option<&'static str> {
    META_HOSTS.iter().find(|&&candidate| candidate == host)?;
    Some(if host == "instagram.c10r.instagram.com" {
        "instagram.com"
    } else {
        META_HOSTS
            .iter()
            .copied()
            .find(|&candidate| candidate == host)?
    })
}

/// Подключается к IPv4:443 с нейтральным SNI, но проверяет сертификат для `host`.
pub async fn check_meta_edge(
    host: &str,
    address: Ipv4Addr,
    ca_bundle: &Path,
) -> Result<(), String> {
    let verify_name =
        certificate_name(host).ok_or_else(|| "unsupported Meta hostname".to_string())?;
    let peer = SocketAddr::V4(SocketAddrV4::new(address, 443));
    timeout(
        TOTAL_TIMEOUT,
        check_meta_edge_at(verify_name, peer, ca_bundle),
    )
    .await
    .map_err(|_| "истёк тайм-аут проверки Meta через TLS".to_string())?
}

async fn check_meta_edge_at(
    verify_name: &str,
    peer: SocketAddr,
    ca_bundle: &Path,
) -> Result<(), String> {
    let tls_config = tls_config(ca_bundle, verify_name)?;
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer))
        .await
        .map_err(|_| "истёк тайм-аут подключения TCP к Meta".to_string())?
        .map_err(|error| format!("не удалось подключиться к Meta по TCP: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("не удалось настроить TCP для Meta: {error}"))?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from(NEUTRAL_SNI.to_string())
        .map_err(|error| format!("недопустимое нейтральное имя SNI: {error}"))?;
    timeout(TOTAL_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| "истёк тайм-аут рукопожатия TLS с Meta".to_string())?
        .map(|_| ())
        .map_err(|error| format!("проверка TLS-сертификата Meta не пройдена: {error}"))
}

fn tls_config(ca_bundle: &Path, verify_name: &str) -> Result<rustls::ClientConfig, String> {
    let file = File::open(ca_bundle).map_err(|error| {
        format!(
            "не удалось прочитать набор сертификатов CA {}: {error}",
            ca_bundle.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| {
            format!(
                "не удалось разобрать набор сертификатов CA {}: {error}",
                ca_bundle.display()
            )
        })?;
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!(
            "CA bundle {} has no usable certificates",
            ca_bundle.display()
        ));
    }

    let standard = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| format!("не удалось создать проверку сертификатов Meta: {error}"))?;
    let expected_name = verify_name.to_owned();
    let verifier = Arc::new(HostBoundVerifier {
        standard,
        expected_name,
    });
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

#[derive(Debug)]
struct HostBoundVerifier {
    standard: Arc<WebPkiServerVerifier>,
    expected_name: String,
}

impl ServerCertVerifier for HostBoundVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sni_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let expected_name = ServerName::try_from(self.expected_name.clone())
            .map_err(|_| Error::General("недопустимое имя узла в сертификате".to_string()))?;
        self.standard.verify_server_cert(
            end_entity,
            intermediates,
            &expected_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.standard.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.standard.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}

impl fmt::Display for HostBoundVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "certificate bound to {}", self.expected_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn test_certificate(
        domain: &str,
    ) -> (
        std::path::PathBuf,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let certificate = generate_simple_self_signed(vec![domain.to_string()]).unwrap();
        let path =
            std::env::temp_dir().join(format!("r2o-meta-edge-{}-{id}.pem", std::process::id()));
        std::fs::write(&path, certificate.serialize_pem().unwrap()).unwrap();
        (
            path,
            CertificateDer::from(certificate.serialize_der().unwrap()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certificate.serialize_private_key_der(),
            )),
        )
    }

    #[test]
    fn allowlist_maps_the_c10r_alias_to_instagram_certificate_name() {
        assert_eq!(certificate_name("instagram.com"), Some("instagram.com"));
        assert_eq!(
            certificate_name("instagram.c10r.instagram.com"),
            Some("instagram.com")
        );
        assert_eq!(certificate_name("example.com"), None);
        assert_eq!(certificate_name("Instagram.com"), None);
    }

    #[tokio::test]
    async fn neutral_sni_still_requires_the_requested_certificate_name() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_path, leaf, key) = test_certificate("instagram.com");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .unwrap();

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let tls = acceptor.accept(stream).await.unwrap();
            tls.get_ref().1.server_name().map(str::to_owned)
        });

        check_meta_edge_at("instagram.com", address, &ca_path)
            .await
            .unwrap();
        assert_eq!(server.await.unwrap().as_deref(), Some(NEUTRAL_SNI));
        let _ = std::fs::remove_file(ca_path);
    }

    #[tokio::test]
    async fn wrong_certificate_name_is_rejected_even_with_valid_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_path, leaf, key) = test_certificate("example.com");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let _ = acceptor.accept(stream).await;
        });

        assert!(
            check_meta_edge_at("instagram.com", address, &ca_path)
                .await
                .is_err()
        );
        let _ = server.await;
        let _ = std::fs::remove_file(ca_path);
    }
}
