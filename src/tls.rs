use rustls::pki_types::CertificateDer;
use rustls_pemfile::{Item::X509Certificate, read_one};
use std::{io::BufReader, iter};
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::Item;

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