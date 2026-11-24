use crate::Error;
use crate::error::MessageTooLarge;
use bytes::{Buf, Bytes, BytesMut};
use fallible_iterator::FallibleIterator;
use postgres_protocol::message::backend;
use postgres_protocol::message::frontend::CopyData;
use std::fmt;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

pub enum FrontendMessage {
    Raw(Bytes),
    CopyData(CopyData<Box<dyn Buf + Send>>),
}

pub enum BackendMessage {
    Normal {
        messages: BackendMessages,
        request_complete: bool,
    },
    /// One NoticeResponse or ParameterStatus, which follows a raw exchange in
    /// flight and is otherwise asynchronous.
    Informational(BackendMessages),
    Async(backend::Message),
}

pub struct BackendMessages(BytesMut);

impl BackendMessages {
    pub fn empty() -> BackendMessages {
        BackendMessages(BytesMut::new())
    }

    /// The first message, leaving these messages as they are.
    pub fn peek(&self) -> io::Result<Option<backend::Message>> {
        backend::Message::parse(&mut self.0.clone())
    }
}

impl FallibleIterator for BackendMessages {
    type Item = backend::Message;
    type Error = io::Error;

    fn next(&mut self) -> io::Result<Option<backend::Message>> {
        backend::Message::parse(&mut self.0)
    }
}

/// A backend message whose header the codec could not read.
#[derive(Debug)]
struct InvalidMessage(io::Error);

impl fmt::Display for InvalidMessage {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(fmt)
    }
}

impl std::error::Error for InvalidMessage {}

/// The error of reading from a framed stream: what the codec refused is a
/// parse error, and anything else the stream's own.
pub fn read_error(e: io::Error) -> Error {
    if e.get_ref()
        .is_some_and(|inner| inner.is::<MessageTooLarge>() || inner.is::<InvalidMessage>())
    {
        Error::parse(e)
    } else {
        Error::io(e)
    }
}

pub struct PostgresCodec {
    max_message: usize,
}

impl PostgresCodec {
    /// A codec refusing a backend message longer than `max_message` bytes,
    /// its type byte included, before buffering it.
    pub fn new(max_message: usize) -> PostgresCodec {
        PostgresCodec { max_message }
    }
}

impl Encoder<FrontendMessage> for PostgresCodec {
    type Error = io::Error;

    fn encode(&mut self, item: FrontendMessage, dst: &mut BytesMut) -> io::Result<()> {
        match item {
            FrontendMessage::Raw(buf) => dst.extend_from_slice(&buf),
            FrontendMessage::CopyData(data) => data.write(dst),
        }

        Ok(())
    }
}

impl Decoder for PostgresCodec {
    type Item = BackendMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BackendMessage>, io::Error> {
        let mut idx = 0;
        let mut request_complete = false;

        while let Some(header) = backend::Header::parse(&src[idx..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, InvalidMessage(e)))?
        {
            let len = header.len() as usize + 1;
            if len > self.max_message {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    MessageTooLarge {
                        length: len,
                        maximum: self.max_message,
                    },
                ));
            }
            if src[idx..].len() < len {
                break;
            }

            match header.tag() {
                backend::NOTICE_RESPONSE_TAG | backend::PARAMETER_STATUS_TAG => {
                    if idx == 0 {
                        return Ok(Some(BackendMessage::Informational(BackendMessages(
                            src.split_to(len),
                        ))));
                    } else {
                        break;
                    }
                }
                backend::NOTIFICATION_RESPONSE_TAG => {
                    if idx == 0 {
                        let message = backend::Message::parse(src)?.unwrap();
                        return Ok(Some(BackendMessage::Async(message)));
                    } else {
                        break;
                    }
                }
                _ => {}
            }

            idx += len;

            if header.tag() == backend::READY_FOR_QUERY_TAG {
                request_complete = true;
                break;
            }
        }

        if idx == 0 {
            Ok(None)
        } else {
            Ok(Some(BackendMessage::Normal {
                messages: BackendMessages(src.split_to(idx)),
                request_complete,
            }))
        }
    }
}
