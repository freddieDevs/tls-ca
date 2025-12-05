use rustls::pki_types::CertificateDer;
use rustls_pemfile::{Item::X509Certificate, read_one};
use std::{io::BufReader, iter};
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::Item;
use rustls::RootCertStore;
use miette::IntoDiagnostic;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};


pub mod binary_data {
    //server-key files
    pub const SERVER_CERT_PEM_FILENAME: &str = "server.pem";
    pub const SERVER_CERT_PEM: &[u8] = include_bytes!("certs/generated/server.pem");

    pub const SERVER_KEY_PEM_FILENAME: & str = "server-key.pem";
    pub const SERVER_KEY_PEM: &[u8] = include_bytes!("certs/generated/server-key.pem");

    //client files
    pub const CA_CERT_PEM_FILENAME: &str = "ca.pem";
    pub const CA_CERT_PEM: &[u8] = include_bytes!("certs/generated/ca.pem");
}

pub mod cert_ops {
    use super::*;

    /// It is in the `PEM-encoded X.509` format for certificates. While the data is from a
    /// PEM encoded file, `rustls` loads this into a the [CertificateDer] struct. PEM file
    /// format is human readable and Base64 encoded. DER format is binary.
    fn load_certs_from_pem_data(pem_data: &[u8]) -> Vec<CertificateDer<'static>> {
        let mut reader = BufReader::new(pem_data);
        let mut return_value = vec![];
        for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
            match item {
                Ok(X509Certificate(cert)) => {
                    return_value.push(cert);
                }
                _ => continue,
            }
        }

        return_value
    }

    pub fn server_load_server_cert_chain() -> miette::Result<Vec<CertificateDer<'static>>>{
        let return_certs = cert_ops::load_certs_from_pem_data(binary_data::SERVER_CERT_PEM);

        if return_certs.is_empty() {
            miette::bail!(
                "No certificates found in the {} file",
                binary_data::SERVER_CERT_PEM_FILENAME
            );
        }

        Ok(return_certs)
    }

    pub fn client_load_ca_cert_chain() -> miette::Result<Vec<CertificateDer<'static>>> {
        let return_certs = cert_ops::load_certs_from_pem_data(binary_data::CA_CERT_PEM);

        if return_certs.is_empty() {
            miette::bail!(
                "No ca certificates found in {} file",
                binary_data::CA_CERT_PEM_FILENAME
            );
        }

        Ok(return_certs)
    }
}

 pub mod key_ops {
    use super::*;

    pub fn server_load_single_key() -> miette::Result<PrivateKeyDer<'static>> {
        let mut return_keys = get_key_from_load_pem_data(binary_data::SERVER_KEY_PEM);

        if return_keys.is_empty() {
            miette::bail!(
                "No server private key found in {:?}",
                binary_data::SERVER_KEY_PEM_FILENAME
            );
        }
        Ok(return_keys.remove(0))
    }

    fn get_key_from_load_pem_data(pem_data: &[u8]) -> Vec<PrivateKeyDer> {
        let mut reader = BufReader::new(pem_data);
        let mut return_keys = vec![];

        for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
            match item {
                Ok(Item::Pkcs1Key(key)) => {
                    return_keys.push(PrivateKeyDer::Pkcs1(key));
                }
                _ => continue,
            }
        }

        return_keys
    }
}

pub mod tls_ops {
    use super::*;
    
    use rustls::{ClientConfig, ServerConfig};

    // client calls this to upgrade a tcp stream to a tlsstream
    pub fn create_client_tls_connector() -> miette::Result<TlsConnector> {
        // load the ca cert 
        let root_cert_store = root_cert_store_ops::create_client_root_cert_store()?;

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        // requirement of the connector to wrap in an arc
        let client_config = Arc::new(client_config);
        let tls_connector = TlsConnector::from(client_config);

        Ok(tls_connector)
    }

    // server tls acceptor
    pub fn create_server_tls_acceptor() -> miette::Result<TlsAcceptor> {
        //server cert chain, server private key
        let server_cert_chain = cert_ops::server_load_server_cert_chain()?;
        let server_key = key_ops::server_load_single_key()?;
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_cert_chain, server_key)
            .into_diagnostic()?;
        let server_config = Arc::new(server_config);
        let tls_acceptor = TlsAcceptor::from(server_config);
        Ok(tls_acceptor)
    }

}

pub mod root_cert_store_ops {
    use super::*;

    pub fn create_client_root_cert_store() -> miette::Result<RootCertStore> {
        let mut root_cert_store = RootCertStore::empty();
        let ca_cer_chain = cert_ops::client_load_ca_cert_chain()?;

        for cert in ca_cer_chain {
            root_cert_store.add(cert).into_diagnostic();
        }

        Ok(root_cert_store)
    }
}