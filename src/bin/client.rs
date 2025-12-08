use miette::IntoDiagnostic;
use rustls::{pki_types::ServerName};
use tls_ca::{common_io, tls};

//todo change this to only implement tokio_rustls & learn about the futures
#[tokio::main]
async fn main() -> miette::Result<()> {
    let address = format!("{}:{}", common_io::constants::HOST, common_io::constants::PORT);
    let server_name = ServerName::try_from(common_io::constants::SERVERNAME).into_diagnostic()?;

    // register ctrl +c handler
    tokio::spawn(async {
        _ = tokio::signal::ctrl_c().await;
        println!("CtrlC was pressed ...exiting");
        std::process::exit(0);
    });

    //insecure connection to the server
    let stream = tokio::net::TcpStream::connect(address.as_str())
        .await
        .into_diagnostic()?;
    // securing the stream
    let tls_connector = tls::tls_ops::create_client_tls_connector()?;
    
    let secure_stream = tls_connector
        .connect(server_name, stream)
        .await
        .into_diagnostic()?;

    let (_reader, _writer) = tokio::io::split(secure_stream);

    //todo: split tcp stream to be able to perform read/write ops
    Ok(())
}