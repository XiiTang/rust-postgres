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
  What it keeps of them is bounded by `RawConfig::max_retained`: past it the
  startup fails with a parse error whose cause is `StartupTooLarge`.
  Regression: `startup_requests_the_minor_version_and_reports_the_whole_key`,
  `negotiate_protocol_version_ends_the_startup`,
  `startup_notices_and_parameters_past_the_maximum_end_the_startup`.
- **Raw exchanges.** `Client::exchange` writes a request's initial messages and
  returns a `RawWriter` for what follows (CopyData, CopyDone, CopyFail, Sync),
  which holds the write side until dropped, and `RawResponses`, every backend
  message through ReadyForQuery, ErrorResponse included. NoticeResponse and
  ParameterStatus arriving while a raw exchange is in flight are among its
  responses; otherwise they are `AsyncMessage::Notice` and the new
  `AsyncMessage::Parameter`. A raw connection keeps no parameter cache, so
  `Connection::parameter` is `None` and a server cannot grow it; upstream
  connections keep theirs. `Error::kind` names the failure kind and
  `DbError::parse` is public. Regression:
  `an_exchange_reads_its_notices_and_errors_in_order_and_holds_the_writer`.

Verification: the five `tokio-postgres --test raw` cases with a scripted
backend, and the upstream suites (`cargo test -p tokio-postgres -p postgres -p
postgres-protocol -p postgres-types --all-features`) against PostgreSQL 18.6
configured by `docker/sql_setup.sh`.

## Fixed constant-time utilities (#312)

Update the workspace lockfile's ctutils 0.4.2 to 0.4.4 for RUSTSEC-2026-0385,
the smallest fixed patch for mask generation and u128 comparisons. No wire,
authentication, raw-connection or parameter-cache behavior changes. Regression
coverage: the postgres, tokio-postgres, postgres-protocol and postgres-types
suites with all features, plus Boundless's complete PostgreSQL module.

## Startup ParameterStatus entry cap (driver plan W17c)

Reason: Boundless's driver plan v23, W17c and Rule 11. A raw startup keeps
each ParameterStatus in order and charged only its name and value bytes against
`RawConfig::max_retained` (4b86aa1 tokio-postgres/src/raw.rs:280-284), so a
server repeating ParameterStatus with an empty name and value grew the startup's
vector without bound while the byte count stayed zero. Upstream's
`connect_raw` keys parameters by name in a map with no count bound
(f1cb6ec0 tokio-postgres/src/connect_raw.rs:353-358); its paths are unchanged.

Change: `RawConfig::max_parameters`, set by the caller with no default, is the
most ParameterStatus messages a raw startup keeps. Each one counts as an entry
even when both strings are empty. The startup's retention owner (`Retained`)
holds the parameters and adds one only through `Retained::parameter`, which
parses borrowed name/value first, then checks occurrence count and retained bytes
before allocating either string or pushing. This preserves malformed-body error
precedence at an already full count. One past the
maximum ends the startup with a parse error whose cause is
`StartupTooManyParameters { count, maximum }`, and no partial `Startup` is
returned. No framing or allocation interface is added.

Regression: `empty_and_duplicate_startup_parameters_hit_count`
(`tokio-postgres --test raw`): three empty ParameterStatus messages under a
maximum of three are kept; a fourth ends the startup with
`StartupTooManyParameters { count: 4, maximum: 3 }`. Before the change the
four-entry startup succeeded and the test failed (exit 101).


### Reconciled W17c2 on the current pin

Source tip 96dcef1df88606e10255c76b5de27e51764df077 is based on
96ec0be1870a31607969de60c8824703fea273cf. The sole `Retained::parameter`
checkpoint parses borrowed fields before the occurrence and byte checks; only
then does it allocate/push. Upstream f1cb6ec0's ordinary parameter map replaces
same-name entries without a count bound; the pre-existing fork raw startup
retains every occurrence in order. Keep both existing behaviors, adding only
the caller-selected raw-startup cap and typed parse cause. No retry, early
successful Startup, authentication classification, framing, post-startup async
ParameterStatus or error-cleanup behavior changes. Malformed borrowed fields
retain their original UTF-8 parser cause even at a full count.

macOS Darwin 27.2.0 arm64 / Rust 1.97.0, all commands through build-slot:

| cargo arguments | Exit / result |
| --- | --- |
| test -p tokio-postgres --test raw --locked | 0; 7 scripted-backend tests |
| clippy -p tokio-postgres --lib --tests --locked -- -D warnings | 0 |
| fmt --all --check | 0 |

The new `malformed_startup_parameter_keeps_parse_precedence` fails (exit 101)
when count-before-parse is restored temporarily, and passes after restoration.
`empty_and_duplicate_startup_parameters_hit_count` accepts exactly N empty or
duplicate nonempty pairs and withholds ReadyForQuery before asserting Startup
is still pending; N+1 returns the original typed count/maximum. No server,
sleep, retry or partial successful Info is involved. This evidence-only commit
follows the tested source tip. No push or boundless-branch movement occurred.
