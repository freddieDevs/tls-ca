use std::time::Duration;
use futures_util::StreamExt as _;
use miette::IntoDiagnostic;
use r3bl_tui::{PinnedInputStream, gen_input_stream_with_delay, ok};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use smallvec::smallvec;

pub mod constants {
    pub const HOST: &str = "localhost";
    pub const PORT: u16 = 8050;
    pub const SERVERNAME: &str = "frejinc.com";  
}

pub async fn read_write<R, W>(mut reader: R, writer: W) -> miette::Result<()> 
where 
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,

{
    let input_stream = gen_input_stream_with_delay(
        smallvec!["one\n", "two\n", "three\n", "\n"], 
        Duration::from_millis(500),
    );

    let mut std_out = tokio::io::stdout();

    tokio::select! {
        _ = read_from_input_stream_until_empty_and_write_to_writer(input_stream, writer) => {},
        _ = tokio::io::copy(&mut reader, &mut std_out) => {},

    }   

    ok!(())
}

async fn read_from_input_stream_until_empty_and_write_to_writer<W: AsyncWrite + Unpin>(
    mut input_stream: PinnedInputStream<&str>,
    mut writer: W,
) -> miette::Result<()> {
    while let Some(item) = input_stream.next().await {
        writer.write_all(item.as_bytes()).await.into_diagnostic()?;
        writer.flush().await.into_diagnostic()?;
    }

    Ok(())
}
