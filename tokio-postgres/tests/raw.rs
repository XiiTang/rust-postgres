//! The raw connection over a scripted backend: no server is needed.
use bytes::{BufMut, Bytes, BytesMut};
use postgres_protocol::message::backend::Message;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_postgres::error::{ErrorKind, MessageTooLarge, ProtocolVersionUnsupported};
use tokio_postgres::raw::{
    Authenticate, AuthenticationRequest, AuthenticationResponse, BoxError, RawConfig,
    connect_raw_with,
};
use tokio_postgres::{AsyncMessage, Connection};

fn message(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag];
    buf.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

fn cstr(value: &str) -> Vec<u8> {
    let mut buf = value.as_bytes().to_vec();
    buf.push(0);
    buf
}

fn ready() -> Vec<u8> {
    message(b'Z', b"I")
}

fn notice(text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (b'S', "NOTICE"),
        (b'V', "NOTICE"),
        (b'C', "00000"),
        (b'M', text),
    ] {
        body.push(field);
        body.extend(cstr(value));
    }
    body.push(0);
    message(b'N', &body)
}

fn parameter(name: &str, value: &str) -> Vec<u8> {
    let mut body = cstr(name);
    body.extend(cstr(value));
    message(b'S', &body)
}

async fn read_startup(peer: &mut DuplexStream) -> Vec<u8> {
    let length = peer.read_u32().await.unwrap() as usize;
    let mut body = vec![0; length - 4];
    peer.read_exact(&mut body).await.unwrap();
    body
}

async fn read_message(peer: &mut DuplexStream) -> (u8, Vec<u8>) {
    let tag = peer.read_u8().await.unwrap();
    let length = peer.read_u32().await.unwrap() as usize;
    let mut body = vec![0; length - 4];
    peer.read_exact(&mut body).await.unwrap();
    (tag, body)
}

/// Answers an MD5 request with a fixed digest, and records each request.
#[derive(Default)]
struct Recorder {
    requests: Vec<String>,
}

impl Authenticate for Recorder {
    fn authenticate<'a>(
        &'a mut self,
        request: AuthenticationRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResponse, BoxError>> + Send + 'a>> {
        Box::pin(async move {
            self.requests.push(format!("{request:?}"));
            Ok(match request {
                AuthenticationRequest::Md5Password { .. } => {
                    AuthenticationResponse::Password(b"md5digest".to_vec())
                }
                _ => AuthenticationResponse::None,
            })
        })
    }
}

fn config(minor_version: u16, max_message: usize) -> RawConfig {
    RawConfig {
        parameters: vec![("user".into(), "alice".into())],
        minor_version,
        max_message,
    }
}

async fn started(
    authenticate: &mut Recorder,
) -> (
    tokio_postgres::Client,
    Connection<DuplexStream, tokio_postgres::tls::NoTlsStream>,
    DuplexStream,
) {
    let (client_side, mut peer) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        read_startup(&mut peer).await;
        let mut reply = message(b'R', &0i32.to_be_bytes());
        reply.extend(message(b'K', &[&7i32.to_be_bytes()[..], &[1; 4]].concat()));
        reply.extend(ready());
        peer.write_all(&reply).await.unwrap();
        peer
    });
    let (client, connection, _) = connect_raw_with(client_side, &config(0, 1 << 16), authenticate)
        .await
        .unwrap();
    (client, connection, server.await.unwrap())
}

#[tokio::test]
async fn startup_requests_the_minor_version_and_reports_the_whole_key() {
    let (client_side, mut peer) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let startup = read_startup(&mut peer).await;
        assert_eq!(&startup[..4], &[0, 3, 0, 2]);
        assert_eq!(&startup[4..], b"client_encoding\0UTF8\0user\0alice\0\0");
        let mut salt = 5i32.to_be_bytes().to_vec();
        salt.extend_from_slice(b"salt");
        peer.write_all(&message(b'R', &salt)).await.unwrap();
        let (tag, body) = read_message(&mut peer).await;
        assert_eq!((tag, body.as_slice()), (b'p', &b"md5digest\0"[..]));
        let mut reply = message(b'R', &0i32.to_be_bytes());
        reply.extend(message(b'K', &[&9i32.to_be_bytes()[..], &[3; 32]].concat()));
        reply.extend(parameter("server_version", "18.6"));
        reply.extend(notice("welcome"));
        reply.extend(ready());
        peer.write_all(&reply).await.unwrap();
        peer
    });
    let mut recorder = Recorder::default();
    let (_client, _connection, startup) =
        connect_raw_with(client_side, &config(2, 1 << 16), &mut recorder)
            .await
            .unwrap();
    server.await.unwrap();
    assert_eq!(
        recorder.requests,
        ["Md5Password { salt: [115, 97, 108, 116] }", "Ok"]
    );
    assert_eq!(startup.process_id, 9);
    assert_eq!(startup.secret_key, [3; 32]);
    assert_eq!(
        startup.parameters,
        [("server_version".to_owned(), "18.6".to_owned())]
    );
    assert_eq!(startup.notices[0].message(), "welcome");
}

#[tokio::test]
async fn negotiate_protocol_version_ends_the_startup() {
    let (client_side, mut peer) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        read_startup(&mut peer).await;
        let mut body = (3u32 << 16).to_be_bytes().to_vec();
        body.extend_from_slice(&0i32.to_be_bytes());
        peer.write_all(&message(b'v', &body)).await.unwrap();
        peer
    });
    let error = connect_raw_with(client_side, &config(2, 1 << 16), &mut Recorder::default())
        .await
        .err()
        .unwrap();
    server.await.unwrap();
    assert_eq!(error.kind(), ErrorKind::ProtocolVersion);
    let unsupported = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<ProtocolVersionUnsupported>()
        .unwrap();
    assert_eq!(unsupported.newest_minor_version, 0);
}

#[tokio::test]
async fn a_message_longer_than_the_maximum_is_refused_from_its_header() {
    let (client_side, mut peer) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        read_startup(&mut peer).await;
        // Only the header: the body is never sent, so a codec that waited
        // for it would hang.
        let mut header = vec![b'R'];
        header.extend_from_slice(&(1u32 << 20).to_be_bytes());
        peer.write_all(&header).await.unwrap();
        peer
    });
    let error = connect_raw_with(client_side, &config(0, 1024), &mut Recorder::default())
        .await
        .err()
        .unwrap();
    let _peer = server.await.unwrap();
    assert_eq!(error.kind(), ErrorKind::Parse);
    let io = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<std::io::Error>()
        .unwrap();
    assert_eq!(
        io.get_ref().unwrap().downcast_ref::<MessageTooLarge>(),
        Some(&MessageTooLarge {
            length: (1 << 20) + 1,
            maximum: 1024
        })
    );
}

fn query(sql: &str) -> Bytes {
    let mut buf = BytesMut::new();
    postgres_protocol::message::frontend::query(sql, &mut buf).unwrap();
    buf.freeze()
}

#[tokio::test]
async fn an_exchange_reads_its_notices_and_errors_in_order_and_holds_the_writer() {
    let mut recorder = Recorder::default();
    let (client, mut connection, mut peer) = started(&mut recorder).await;
    let driver = tokio::spawn(async move {
        let mut received = Vec::new();
        while let Some(message) =
            futures_util::future::poll_fn(|cx| connection.poll_message(cx)).await
        {
            match message.unwrap() {
                AsyncMessage::Parameter { name, value } => received.push(format!("{name}={value}")),
                AsyncMessage::Notice(notice) => received.push(notice.message().to_owned()),
                _ => {}
            }
        }
        received
    });
    let (mut writer, mut responses) = client.exchange(query("COPY t FROM STDIN")).unwrap();
    let (second, mut second_responses) = client.exchange(query("SELECT 2")).unwrap();
    let (tag, _) = read_message(&mut peer).await;
    assert_eq!(tag, b'Q');
    let mut reply = parameter("TimeZone", "UTC");
    reply.extend(notice("first"));
    reply.extend(message(b'G', &[0, 0, 0]));
    peer.write_all(&reply).await.unwrap();
    // The second exchange waits while the first one's writer is held: its
    // query follows the writer's CopyDone.
    writer
        .send(Bytes::from_static(b"c\0\0\0\x04"))
        .await
        .unwrap();
    let (tag, _) = read_message(&mut peer).await;
    assert_eq!(tag, b'c');
    drop(writer);
    let (tag, _) = read_message(&mut peer).await;
    assert_eq!(tag, b'Q');
    let mut reply = message(b'E', b"SERROR\0C22000\0Mbad\0\0");
    reply.extend(ready());
    reply.extend(message(b'C', b"SELECT 0\0"));
    reply.extend(ready());
    reply.extend(parameter("application_name", "idle"));
    peer.write_all(&reply).await.unwrap();

    let mut kinds = Vec::new();
    while let Some(message) = responses.next().await.unwrap() {
        kinds.push(match message {
            Message::ParameterStatus(_) => "parameter",
            Message::NoticeResponse(_) => "notice",
            Message::CopyInResponse(_) => "copy_in",
            Message::ErrorResponse(_) => "error",
            Message::ReadyForQuery(_) => "ready",
            _ => "other",
        });
    }
    assert_eq!(kinds, ["parameter", "notice", "copy_in", "error", "ready"]);
    assert!(matches!(
        second_responses.next().await.unwrap(),
        Some(Message::CommandComplete(_))
    ));
    assert!(matches!(
        second_responses.next().await.unwrap(),
        Some(Message::ReadyForQuery(_))
    ));
    drop((client, second));
    let mut end = BytesMut::new();
    end.put_u8(b'X');
    let (tag, _) = read_message(&mut peer).await;
    assert_eq!(tag, end[0]);
    drop(peer);
    assert_eq!(driver.await.unwrap(), ["application_name=idle"]);
}
