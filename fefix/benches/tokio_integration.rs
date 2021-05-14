use self::fix_codec::{FixCodec, Framed};
use fefix::tagvalue::{Config, Decoder};
use fefix::Dictionary;
use futures::{AsyncRead, AsyncReadExt};
use futures_util::StreamExt;
use std::{net::{Ipv4Addr, SocketAddrV4}, time::Instant};
use std::pin::Pin;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{compat::TokioAsyncReadCompatExt};

static MESSAGE_COUNT: u32 = 250_000;
static PASS_COUNT: u32 = 100;

#[tokio::main]
async fn main() {
    let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let listener = TcpListener::bind(listen_addr).await.unwrap();
    let socket_address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        println!("Listening...");

        while let Ok((mut client, client_addr)) = listener.accept().await {
            println!("Received connection from {:?}", client_addr);
            client.set_nodelay(true).unwrap();

            for _ in 0..MESSAGE_COUNT {
                let data = "8=FIX.4.4\x019=289\x0135=8\x0134=1090\x0149=TESTSELL1\x0152=20180920-18:23:53.671\x0156=TESTBUY1\x016=113.35\x0111=636730640278898634\x0114=3500.0000000000\x0115=USD\x0117=20636730646335310000\x0121=2\x0131=113.35\x0132=3500\x0137=20636730646335310000\x0138=7000\x0139=1\x0140=1\x0154=1\x0155=MSFT\x0160=20180920-18:23:53.531\x01150=F\x01151=3500\x01453=1\x01448=BRK2\x01447=D\x01452=1\x0110=151\x01";
                let res = client.write_all(data.as_bytes()).await;

                if res.is_err() {
                    break;
                }
            }

            println!("Done");
        }
    });

    let mut fefix_results = vec![];
    for _ in 0..PASS_COUNT {
        let fix_dictionary = Dictionary::fix44();
        let decoder: Decoder<Config> = Decoder::new(fix_dictionary);

        let start = Instant::now();
        let tcp_stream = TcpStream::connect(socket_address).await.unwrap();
        tcp_stream.set_nodelay(true).unwrap();
        let (reader, _writer) = tokio::io::split(tcp_stream);

        let count = run(reader.compat(), decoder).await;
        fefix_results.push(start.elapsed() / count);
    }

    let mut framed_results = vec![];
    for _ in 0..PASS_COUNT {
        let fix_dictionary = Dictionary::fix44();
        let mut decoder: Decoder<Config> = Decoder::new(fix_dictionary);

        let start = Instant::now();
        let tcp_stream = TcpStream::connect(socket_address).await.unwrap();
        tcp_stream.set_nodelay(true).unwrap();

        let mut client = Framed::new(tcp_stream, FixCodec::new('\x01' as u8));

        let mut count = 0;
        while let Some(Ok(msg)) = client.next().await {
            decoder.decode(&msg[..]).expect("Invalid FIX message");

            count += 1;

            if count >= MESSAGE_COUNT {
                break;
            }
        }

        framed_results.push(start.elapsed() / count);
    }

    println!("Fefix: {:?}", fefix_results);
    println!("Framed: {:?}", framed_results);
}

async fn run<I: AsyncRead + Unpin>(mut input: I, decoder: Decoder<Config>) -> u32 {
    let mut decoder = decoder.buffered();
    decoder.config_mut().set_separator(b'\x01');
    decoder.config_mut().set_verify_checksum(true);
    decoder.config_mut().set_decode_assoc(true);
    decoder.config_mut().set_decode_seq(false);
    let mut count = 0;

    loop {
        let mut input = Pin::new(&mut input);
        let buffer = decoder.supply_buffer();
        input.read_exact(buffer).await.unwrap();

        if let Ok(Some(_)) = decoder.current_message() {
            let _msg = decoder.message();
            decoder.clear();

            count += 1;

            if count >= MESSAGE_COUNT {
                break;
            }
        }
    }

    count
}

mod fix_codec {
    use bytes::{Bytes, BytesMut};
    use std::{fmt::Write, io};
    use tokio_util::codec::{Decoder, Encoder};

    pub use tokio_util::codec::Framed;

    #[derive(Debug)]
    pub enum Error {
        IO(io::Error),
        Encoding,
        Format,
        Parsing,
        Checksum,
        UnsupportedFixVersion(String),
    }

    impl From<io::Error> for Error {
        fn from(item: io::Error) -> Self {
            Self::IO(item)
        }
    }

    pub struct FixCodec {
        separator: u8,
    }

    impl FixCodec {
        pub fn new(separator: u8) -> Self {
            Self {
                separator,
            }
        }
    }

    impl Encoder<&str> for FixCodec {
        type Error = Error;

        fn encode(&mut self, item: &str, dst: &mut BytesMut) -> Result<(), Self::Error> {
            dst.write_str(item).map_err(|_| Error::Format)
        }
    }

    impl Decoder for FixCodec {
        type Item = Bytes;
        type Error = Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if src.len() < 20 {
                return Ok(None);
            }

            if &src[..9] != b"8=FIX.4.4" {
                let version = std::str::from_utf8(&src[..9]).map_err(|_| Error::Encoding)?;

                return Err(Error::UnsupportedFixVersion(version.to_string()));
            }

            if &src[10..12] != b"9=" {
                return Err(Error::Parsing);
            }

            let mut body_length: usize = 0;
            let mut body_start: usize = 13;
            for byte in &src[12..] {
                if byte == &self.separator {
                    break;
                }

                body_start += 1;
                body_length = body_length
                    .wrapping_mul(10)
                    .wrapping_add(byte.wrapping_sub(b'0') as usize);
            }

            let body_end = body_start + body_length;

            // Standard footer (checksum) is always 7 bytes long
            let message_size = body_end + 7;

            if src.len() < message_size {
                return Ok(None);
            }

            let message_raw = src.split_to(message_size);
            let checksum_slice = &message_raw[body_end..];

            if &checksum_slice[..3] != b"10=" {
                return Err(Error::Parsing);
            }

            let mut checksum_val: u32 = 0;
            for byte in &checksum_slice[3..6] {
                checksum_val = checksum_val
                    .wrapping_mul(10)
                    .wrapping_add(byte.wrapping_sub(b'0') as u32);
            }

            if checksum_val != checksum(&message_raw[..body_end]) {
                return Err(Error::Checksum);
            }

            Ok(Some(message_raw.freeze()))
        }
    }

    fn checksum(data: &[u8]) -> u32 {
        let checksum: u32 = data.iter().map(|c| *c as u32).sum();

        checksum & 255
    }
}
