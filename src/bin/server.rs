use miette::IntoDiagnostic;
use tls_ca::common_io;
// todo change this to only implement tokio_rustls
#[tokio::main]
async fn main() -> miette::Result<()> {
    let addr = format!("{}:{}", common_io::constants::HOST, common_io::constants::PORT);

    //register CtlrC
    tokio::spawn(async {
        _ = tokio::signal::ctrl_c().await;
        println!("Ctrl + C received ..exiting ...");
        std::process::exit(0);
    });

    //accept insecure connection
    let listener =tokio::net::TcpListener::bind(addr.as_str())
        .await
        .into_diagnostic()?;
    //accept() is blocking
    let (tcp_stream, _) = listener.accept()
    .await
    .into_diagnostic()?;

    let (_reader, _writer) = tokio::io::split(tcp_stream);
    
    Ok(())
}