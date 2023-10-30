use quinn::{ClientConfig, Endpoint};
use std::sync::Arc;

pub fn setup_server_endpoint() -> crate::Result<quinn::Endpoint> {
    let server_config = configure_server()?;
    let endpoint = Endpoint::server(server_config, ([127, 0, 0, 1], 5000).into())?;
    Ok(endpoint)
}

fn configure_server() -> crate::Result<quinn::ServerConfig> {
    let crt = std::fs::read("cert/cert.der")?;
    let key = std::fs::read("cert/key.der")?;

    let priv_key = rustls::PrivateKey(key);
    let cert_chain = vec![rustls::Certificate(crt)];

    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, priv_key)?;
    if let Some(transport_config) = Arc::get_mut(&mut server_config.transport) {
        transport_config.max_concurrent_uni_streams(0_u8.into());
    }

    Ok(server_config)
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}

pub fn setup_client_endpoint() -> crate::Result<Endpoint> {
    let client_cfg = configure_client();
    let mut endpoint = Endpoint::client(([127, 0, 0, 1], 0).into())?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}
