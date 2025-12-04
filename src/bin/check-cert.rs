use tls_ca::{key_ops::server_load_single_key, tls::cert_ops::{client_load_ca_cert_chain, server_load_server_cert_chain}};

fn main() -> miette::Result<()> {
    // load server-key from server-key.pem
    // let server_key=  server_load_single_private_key()?;

    // load server cert from server.pem
    let server_cert_chain = server_load_server_cert_chain()?;
    println!(
        "{}, {:?}",
        "Server Certificate",
        server_cert_chain
    );

    let server_key = server_load_single_key()?;
    println!(
        "{}, {:?}",
        "Server Private Key",
        server_key
    );

    //load cert pem in client-code
    let client_cert_chain = client_load_ca_cert_chain()?;
    println!(
        "{}, {:?}",
        "Client Certificate",
        client_cert_chain
    );
    Ok(())
}