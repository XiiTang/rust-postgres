//! A connection over a stream the caller already secured, authenticated by
//! the caller, and raw exchanges of frontend and backend messages on it.
//!
//! The caller owns TLS and every authentication exchange; the library frames
//! the startup and authentication messages, keeps the connection's message
//! order, bounds each backend message by `RawConfig::max_message` and what
//! the startup keeps by `RawConfig::max_retained` and
//! `RawConfig::max_parameters`.
use crate::codec::{BackendMessage, BackendMessages, FrontendMessage, PostgresCodec, read_error};
use crate::config::{SslMode, SslNegotiation};
use crate::error::{
    DbError, ProtocolVersionUnsupported, StartupTooLarge, StartupTooManyParameters,
};
use crate::maybe_tls_stream::MaybeTlsStream;
use crate::tls::NoTlsStream;
use crate::{Client, Connection, Error};
use bytes::{Bytes, BytesMut};
use fallible_iterator::FallibleIterator;
use futures_channel::mpsc;
use futures_util::{SinkExt, Stream, StreamExt};
use postgres_protocol::message::backend::{Message, NoticeResponseBody, ParameterStatusBody};
use postgres_protocol::message::frontend;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

/// What a raw connection's startup sends and how it bounds what it reads.
#[derive(Debug, Clone)]
pub struct RawConfig {
    /// Startup parameters, sent as given after `client_encoding=UTF8`.
    pub parameters: Vec<(String, String)>,
    /// The minor version of protocol 3 the startup message requests.
    pub minor_version: u16,
    /// The longest backend message accepted, its type byte included.
    pub max_message: usize,
    /// The most bytes of notice fields and parameter statuses the startup
    /// keeps; past it the startup fails with [`StartupTooLarge`].
    pub max_retained: usize,
    /// The most ParameterStatus messages the startup keeps, each counted
    /// even when its name and value are empty; past it the startup fails
    /// with [`StartupTooManyParameters`].
    pub max_parameters: usize,
}

/// An authentication request of the server's, as the caller answers it.
#[derive(Debug)]
pub enum AuthenticationRequest<'a> {
    /// AuthenticationOk: the server accepted the client. The caller confirms
    /// that every exchange it began has completed.
    Ok,
    /// AuthenticationCleartextPassword.
    CleartextPassword,
    /// AuthenticationMD5Password.
    Md5Password {
        /// The salt.
        salt: [u8; 4],
    },
    /// AuthenticationSASL.
    Sasl {
        /// The mechanisms the server offers, in its order.
        mechanisms: Vec<&'a str>,
    },
    /// AuthenticationSASLContinue.
    SaslContinue {
        /// The server's challenge.
        data: &'a [u8],
    },
    /// AuthenticationSASLFinal.
    SaslFinal {
        /// The server's additional data.
        data: &'a [u8],
    },
    /// A request this module does not frame an answer to.
    Unsupported {
        /// `kerberos_v5`, `scm_credential`, `gss`, `sspi` or `gss_continue`.
        method: &'static str,
    },
}

/// The caller's answer to an authentication request, which the library frames.
pub enum AuthenticationResponse {
    /// Nothing is sent.
    None,
    /// A PasswordMessage carrying these bytes.
    Password(Vec<u8>),
    /// A SASLInitialResponse.
    SaslInitial {
        /// The chosen mechanism.
        mechanism: String,
        /// The client's first message.
        data: Vec<u8>,
    },
    /// A SASLResponse.
    Sasl(Vec<u8>),
}

/// A boxed error an authenticator returns.
pub type BoxError = Box<dyn std::error::Error + Sync + Send>;

/// Answers the server's authentication requests.
pub trait Authenticate: Send {
    /// Answers `request`; an error ends the connection with an
    /// authentication error whose cause it is.
    fn authenticate<'a>(
        &'a mut self,
        request: AuthenticationRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<AuthenticationResponse, BoxError>> + Send + 'a>>;
}

/// What the server reported while the connection started.
#[derive(Debug)]
pub struct Startup {
    /// The backend's process ID.
    pub process_id: i32,
    /// The whole cancel key: 4 bytes under protocol 3.0, up to 256 under 3.2.
    pub secret_key: Vec<u8>,
    /// Each ParameterStatus, in order.
    pub parameters: Vec<(String, String)>,
    /// Each NoticeResponse, in order.
    pub notices: Vec<DbError>,
}

/// The startup's reader. Upstream's `StartupStream` yields `io::Result`,
/// which its callers classify as I/O; this one keeps a malformed message a
/// parse error, as the connection's reads do through `read_error`.
struct Reader<S> {
    inner: Framed<MaybeTlsStream<S, NoTlsStream>, PostgresCodec>,
    buf: BackendMessages,
}

impl<S> Reader<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn next(&mut self) -> Result<Message, Error> {
        loop {
            if let Some(message) = self.buf.next().map_err(Error::parse)? {
                return Ok(message);
            }
            match self.inner.next().await {
                Some(Ok(BackendMessage::Normal { messages, .. }))
                | Some(Ok(BackendMessage::Informational(messages))) => self.buf = messages,
                Some(Ok(BackendMessage::Async(message))) => return Ok(message),
                Some(Err(e)) => return Err(read_error(e)),
                None => return Err(Error::closed()),
            }
        }
    }

    async fn send(&mut self, buf: BytesMut) -> Result<(), Error> {
        self.inner
            .send(FrontendMessage::Raw(buf.freeze()))
            .await
            .map_err(Error::io)
    }
}

/// Starts a connection on `stream`, which the caller has already secured:
/// sends the startup message, has `authenticate` answer every authentication
/// request and reads the server's report through its first ReadyForQuery.
/// The user name is whatever `config.parameters` gives; none is derived.
pub async fn connect_raw_with<S>(
    stream: S,
    config: &RawConfig,
    authenticate: &mut dyn Authenticate,
) -> Result<(Client, Connection<S, NoTlsStream>, Startup), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = Reader {
        inner: Framed::new(
            MaybeTlsStream::Raw(stream),
            PostgresCodec::new(config.max_message),
        ),
        buf: BackendMessages::empty(),
    };
    let mut parameters = vec![("client_encoding", "UTF8")];
    parameters.extend(
        config
            .parameters
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let mut buf = BytesMut::new();
    frontend::startup_message_with_version(config.minor_version, parameters, &mut buf)
        .map_err(Error::encode)?;
    reader.send(buf).await?;

    let mut notices = Vec::new();
    let mut retained = Retained {
        bytes: 0,
        maximum: config.max_retained,
        parameters: Vec::new(),
        max_parameters: config.max_parameters,
    };
    loop {
        let message = reader.next().await?;
        let mechanisms;
        let request = match &message {
            Message::AuthenticationOk => AuthenticationRequest::Ok,
            Message::AuthenticationCleartextPassword => AuthenticationRequest::CleartextPassword,
            Message::AuthenticationMd5Password(body) => {
                AuthenticationRequest::Md5Password { salt: body.salt() }
            }
            Message::AuthenticationSasl(body) => {
                mechanisms = body.mechanisms().collect().map_err(Error::parse)?;
                AuthenticationRequest::Sasl { mechanisms }
            }
            Message::AuthenticationSaslContinue(body) => {
                AuthenticationRequest::SaslContinue { data: body.data() }
            }
            Message::AuthenticationSaslFinal(body) => {
                AuthenticationRequest::SaslFinal { data: body.data() }
            }
            Message::AuthenticationKerberosV5 => AuthenticationRequest::Unsupported {
                method: "kerberos_v5",
            },
            Message::AuthenticationScmCredential => AuthenticationRequest::Unsupported {
                method: "scm_credential",
            },
            Message::AuthenticationGss => AuthenticationRequest::Unsupported { method: "gss" },
            Message::AuthenticationSspi => AuthenticationRequest::Unsupported { method: "sspi" },
            Message::AuthenticationGssContinue(_) => AuthenticationRequest::Unsupported {
                method: "gss_continue",
            },
            Message::NegotiateProtocolVersion(body) => {
                return Err(Error::protocol_version(ProtocolVersionUnsupported {
                    newest_minor_version: body.newest_minor_version(),
                    options: body
                        .options()
                        .map(|option| Ok(option.to_owned()))
                        .collect()
                        .map_err(Error::parse)?,
                }));
            }
            Message::NoticeResponse(body) => {
                retained.notice(body)?;
                notices.push(DbError::parse(&mut body.fields()).map_err(Error::parse)?);
                continue;
            }
            Message::ErrorResponse(_) => {
                let Message::ErrorResponse(body) = message else {
                    unreachable!()
                };
                return Err(Error::db(body));
            }
            _ => return Err(Error::unexpected_message()),
        };
        let accepted = matches!(request, AuthenticationRequest::Ok);
        let response = authenticate
            .authenticate(request)
            .await
            .map_err(Error::authentication)?;
        let mut buf = BytesMut::new();
        match response {
            AuthenticationResponse::None => {}
            AuthenticationResponse::Password(password) => {
                frontend::password_message(&password, &mut buf).map_err(Error::encode)?
            }
            AuthenticationResponse::SaslInitial { mechanism, data } => {
                frontend::sasl_initial_response(&mechanism, &data, &mut buf)
                    .map_err(Error::encode)?
            }
            AuthenticationResponse::Sasl(data) => {
                frontend::sasl_response(&data, &mut buf).map_err(Error::encode)?
            }
        }
        if !buf.is_empty() {
            reader.send(buf).await?;
        }
        if accepted {
            break;
        }
    }

    let mut process_id = 0;
    let mut secret_key = Vec::new();
    loop {
        match reader.next().await? {
            Message::BackendKeyData(body) => {
                process_id = body.process_id();
                secret_key = body.secret_key_bytes().to_vec();
            }
            Message::ParameterStatus(body) => retained.parameter(&body)?,
            Message::NoticeResponse(body) => {
                retained.notice(&body)?;
                notices.push(DbError::parse(&mut body.fields()).map_err(Error::parse)?)
            }
            Message::ReadyForQuery(_) => break,
            Message::ErrorResponse(body) => return Err(Error::db(body)),
            _ => return Err(Error::unexpected_message()),
        }
    }

    let (sender, receiver) = mpsc::unbounded();
    let first_word = secret_key
        .get(..4)
        .map_or(0, |key| i32::from_be_bytes(key.try_into().unwrap()));
    let client = Client::new(
        sender,
        SslMode::Disable,
        SslNegotiation::Postgres,
        process_id,
        first_word,
    );
    // The codec ends a batch at ReadyForQuery, so nothing read is left over.
    let connection = Connection::new(reader.inner, VecDeque::new(), None, receiver);
    Ok((
        client,
        connection,
        Startup {
            process_id,
            secret_key,
            parameters: retained.parameters,
            notices,
        },
    ))
}

/// The bytes a startup keeps and the parameters it keeps, and their bounds.
/// Parameters are added only through [`Retained::parameter`].
struct Retained {
    bytes: usize,
    maximum: usize,
    parameters: Vec<(String, String)>,
    max_parameters: usize,
}

impl Retained {
    fn keep(&mut self, bytes: usize) -> Result<(), Error> {
        let retained = self.bytes.saturating_add(bytes);
        if retained > self.maximum {
            return Err(Error::parse(io::Error::new(
                io::ErrorKind::InvalidData,
                StartupTooLarge {
                    retained,
                    maximum: self.maximum,
                },
            )));
        }
        self.bytes = retained;
        Ok(())
    }

    /// Keeps a ParameterStatus once its entry and its bytes fit.
    fn parameter(&mut self, body: &ParameterStatusBody) -> Result<(), Error> {
        if self.parameters.len() >= self.max_parameters {
            return Err(Error::parse(io::Error::new(
                io::ErrorKind::InvalidData,
                StartupTooManyParameters {
                    count: self.parameters.len() + 1,
                    maximum: self.max_parameters,
                },
            )));
        }
        let name = body.name().map_err(Error::parse)?;
        let value = body.value().map_err(Error::parse)?;
        self.keep(name.len() + value.len())?;
        self.parameters.push((name.to_owned(), value.to_owned()));
        Ok(())
    }

    fn notice(&mut self, body: &NoticeResponseBody) -> Result<(), Error> {
        let mut bytes = 0;
        let mut fields = body.fields();
        while let Some(field) = fields.next().map_err(Error::parse)? {
            bytes += 1 + field.value_bytes().len();
        }
        self.keep(bytes)
    }
}

pub(crate) fn writer(initial: Bytes) -> (RawWriter, RawReceiver) {
    let (sender, rest) = mpsc::channel(0);
    (
        RawWriter { sender },
        RawReceiver {
            initial: Some(FrontendMessage::Raw(initial)),
            rest,
        },
    )
}

/// Writes what follows a raw exchange's initial messages: CopyData,
/// CopyDone, CopyFail or Sync. Each waits until the connection takes it.
pub struct RawWriter {
    sender: mpsc::Sender<Bytes>,
}

impl RawWriter {
    /// Writes `messages`, one or more frontend messages.
    pub async fn send(&mut self, messages: Bytes) -> Result<(), Error> {
        self.sender
            .send(messages)
            .await
            .map_err(|_| Error::closed())
    }
}

/// The connection's side of a [`RawWriter`].
#[doc(hidden)]
pub struct RawReceiver {
    initial: Option<FrontendMessage>,
    rest: mpsc::Receiver<Bytes>,
}

impl Stream for RawReceiver {
    type Item = FrontendMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<FrontendMessage>> {
        if let Some(initial) = self.initial.take() {
            return Poll::Ready(Some(initial));
        }
        self.rest
            .poll_next_unpin(cx)
            .map(|messages| messages.map(FrontendMessage::Raw))
    }
}

/// The backend messages answering a raw exchange, ErrorResponse included,
/// through its ReadyForQuery.
pub struct RawResponses {
    receiver: mpsc::Receiver<BackendMessages>,
    cur: BackendMessages,
    done: bool,
}

impl RawResponses {
    pub(crate) fn new(receiver: mpsc::Receiver<BackendMessages>) -> RawResponses {
        RawResponses {
            receiver,
            cur: BackendMessages::empty(),
            done: false,
        }
    }

    /// The next message, or `None` after ReadyForQuery. A connection that
    /// ends first answers [`Error::closed`]-kind; its own error is the
    /// connection's.
    pub async fn next(&mut self) -> Result<Option<Message>, Error> {
        if self.done {
            return Ok(None);
        }
        loop {
            if let Some(message) = self.cur.next().map_err(Error::parse)? {
                self.done = matches!(message, Message::ReadyForQuery(_));
                return Ok(Some(message));
            }
            match self.receiver.next().await {
                Some(messages) => self.cur = messages,
                None => return Err(Error::closed()),
            }
        }
    }
}
