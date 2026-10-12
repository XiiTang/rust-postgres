# Boundless patches

Base: upstream `rust-postgres/rust-postgres` tag `tokio-postgres-v0.7.18`, commit
`f1cb6ec0d5766b136cbd68f3010d64142a5daa66` (postgres-protocol 0.6.12,
postgres-types 0.2.14; full upstream history retained). Branch: `boundless`.

Boundless's PostgreSQL driver supplies a stream it has already dialed and
secured, answers every authentication request itself and exchanges extended- and
simple-protocol messages one request at a time. The library keeps framing,
message order and the connection's bookkeeping. Upstream behaviour of the
existing APIs is unchanged.

Changes:

- **Protocol 3.2 keys and negotiation** (postgres-protocol). `BackendKeyData`
  keeps the whole cancel key, 4 to 256 bytes, refusing any other length;
  `NegotiateProtocolVersion` is parsed, its version read whole, the major in the
  high 16 bits, as servers send it (PostgreSQL 14 sends 3.0) and libpq reads it,
  and a major other than 3 refused; `startup_message_with_version` names the
  requested minor version and `cancel_request_with_key` sends the whole key.
  Regression: `backend_key_data_*`, `negotiate_protocol_version_*`,
  `startup_message_names_the_requested_minor_version`,
  `cancel_request_carries_the_whole_key`.
- **Bounded backend messages.** `PostgresCodec` takes a maximum length and
  refuses a longer message from its header, before buffering its body, as a
  parse error whose cause is `MessageTooLarge`. A header the codec cannot read is
  a parse error too, not an I/O one. Upstream paths keep no maximum.
  Regression: `a_message_longer_than_the_maximum_is_refused_from_its_header`.
- **Caller-authenticated startup.** `raw::connect_raw_with` starts a connection
  on a supplied, already secured stream: it sends the configured parameters
  after `client_encoding=UTF8`, with no user name derived from the operating
  system; passes every authentication request, AuthenticationOk included, to
  the caller's `Authenticate` and frames its answer; ends at
  NegotiateProtocolVersion with `ProtocolVersionUnsupported`; and returns the
  process ID, the whole cancel key, the parameters and the notices in order.
  Regression: `startup_requests_the_minor_version_and_reports_the_whole_key`,
  `negotiate_protocol_version_ends_the_startup`.
- **Raw exchanges.** `Client::exchange` writes a request's initial messages and
  returns a `RawWriter` for what follows (CopyData, CopyDone, CopyFail, Sync),
  which holds the write side until dropped, and `RawResponses`, every backend
  message through ReadyForQuery, ErrorResponse included. NoticeResponse and
  ParameterStatus arriving while a raw exchange is in flight are among its
  responses; otherwise they are `AsyncMessage::Notice` and the new
  `AsyncMessage::Parameter`. `Error::kind` names the failure kind and
  `DbError::parse` is public. Regression:
  `an_exchange_reads_its_notices_and_errors_in_order_and_holds_the_writer`.

Verification: the four `tokio-postgres --test raw` cases with a scripted
backend, and the upstream suites (`cargo test -p tokio-postgres -p postgres -p
postgres-protocol -p postgres-types --all-features`) against PostgreSQL 18.6
configured by `docker/sql_setup.sh`.
