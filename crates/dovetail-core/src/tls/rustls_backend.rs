//! The `rustls` backend.
//!
//! Configuration, handshake and record path are all rustls's; nothing here
//! reimplements or wraps them. The job of this module is to turn a
//! [`TlsConfig`] into rustls's own types, to map rustls's errors onto
//! [`TlsError`] without inventing detail, and to hold the transport so a caller
//! can treat this like any other byte stream.

use super::{Stream, TlsConfig, TlsError, TlsProvider};
use std::io::{Read, Write};
use std::sync::Arc;

type RootStore = rustls::RootCertStore;

/// A client session on `rustls`.
pub struct RustlsProvider<S: Stream> {
    conn: rustls::ClientConnection,
    io: S,
}

/// Hand-written rather than derived: `derive(Debug)` would demand `S: Debug`, and
/// the whole point of `S` being any `Read + Write` is that it need not be.
///
/// The negotiated parameters are printed and the transport is not, because a
/// stream's `Debug` may be a formatter for a socket, a file or a test double, and
/// one of those is a reasonable thing to log while the others are not.
impl<S: Stream> std::fmt::Debug for RustlsProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

impl<S: Stream> RustlsProvider<S> {
    /// Build the stack's configuration from the backend-neutral one.
    ///
    /// The provider is passed explicitly rather than installed globally. rustls
    /// keeps a process-wide default, and a component that reads the global one
    /// would depend on whichever component happened to be initialised first —
    /// which is the difference between a benchmark that compares stacks and one
    /// that compares whichever stack won a race.
    fn config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
        // `add` rather than `add_parsable_certificates`: these are anchors the
        // caller chose deliberately, so one that does not parse is a
        // configuration error worth reporting rather than a certificate to skip.
        let mut roots = RootStore::empty();
        for der in &cfg.roots {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
                .map_err(|e| TlsError::BadCertificate.with_detail(format!("trust anchor: {e}")))?;
        }

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_root_certificates(roots);

        Ok(Arc::new(builder.with_no_client_auth()))
    }

    /// Open a client session over `io`, without starting the handshake.
    ///
    /// # Errors
    ///
    /// If the configuration or the server name is rejected. No I/O happens here,
    /// so a failure is a programming error rather than a network condition.
    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| TlsError::Other(format!("rustls server name: {e}")))?;
        let conn =
            rustls::ClientConnection::new(Self::config(cfg)?, name).map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    /// Finish the handshake, reading and writing on the transport until it is
    /// done.
    fn drive(&mut self) -> Result<(), TlsError> {
        while self.conn.is_handshaking() {
            self.conn.complete_io(&mut self.io)?;
        }
        // Leaving the loop is what flushes rustls' post-handshake key update,
        // which must happen before plaintext may be written. `complete_prior_io`
        // is only reachable through rustls' own `Stream` wrapper, which this
        // module does not use because it would put a second stream type between
        // the caller and the record path.
        Ok(())
    }

    /// The transport, once the handshake is done.
    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Stream> TlsProvider for RustlsProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        // Read from the provider, in the provider's own order. Writing this list
        // out by hand would be a claim about rustls rather than a report of it.
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }
}

impl<S: Stream> Read for RustlsProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.drive()?;
        self.conn.reader().read(buf)
    }
}

impl<S: Stream> Write for RustlsProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        self.conn.writer().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()
    }
}

/// Map a rustls error onto the backend-neutral set.
///
/// rustls exposes its causes as enum variants, so this is a real mapping rather
/// than a string match, and every variant it defines in the pinned version is
/// listed so that the classification is deliberate and reviewable rather than
/// whatever the last arm happened to catch.
///
/// # The wildcard is a real limitation
///
/// `rustls::Error` is `#[non_exhaustive]`, so the trailing `_` arm is mandatory.
/// That means a *new* rustls variant would land in `Other` instead of failing the
/// build — including a new certificate error, which is the case most likely to be
/// added and the one a caller most wants classified. So this mapping is re-read
/// when rustls is bumped, which is why the classification table lives in
/// `docs/function/tls-provider.md` rather than only here.
///
/// `TlsError::Timeout` is unreachable from this arm and reaches the caller through
/// [`TlsError`]'s `From<io::Error>` impl instead: rustls surfaces a timeout as the
/// transport's `io::Error`, not as a protocol error.
fn map_error(e: &rustls::Error) -> TlsError {
    use rustls::Error as E;
    match e {
        // Everything rustls can say about a chain it refused to trust.
        E::InvalidCertificate(_)
        | E::InvalidCertRevocationList(_)
        | E::NoCertificatesPresented
        | E::UnsupportedNameType => TlsError::BadCertificate,

        // The peer finished, but with nothing this build will speak.
        E::NoApplicationProtocol
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::BadMaxFragmentSize => TlsError::NoSharedCipher,

        // A record that made no sense, or arrived after the handshake ended.
        // Grouped as `Closed` because the actionable response is the same: this
        // connection is finished, and writing more plaintext onto it will not help.
        E::DecryptError
        | E::EncryptError
        | E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::HandshakeNotComplete
        | E::PeerSentOversizedRecord
        // A close_notify is how a peer hangs up politely, so it belongs with the
        // cases whose only correct response is to stop using the connection.
        | E::AlertReceived(rustls::AlertDescription::CloseNotify) => TlsError::Closed,

        // Any other alert is a refusal rather than a hangup, reported as such so a
        // caller can tell "the peer said no" from "the peer left".
        E::AlertReceived(other) => TlsError::Other(format!("rustls alert: {other:?}")),

        E::FailedToGetCurrentTime
        | E::FailedToGetRandomBytes
        | E::InvalidEncryptedClientHello(_)
        | E::InconsistentKeys(_)
        | E::General(_)
        | E::Other(_) => TlsError::Other(format!("rustls: {e:?}")),

        // Mandatory: `rustls::Error` is `#[non_exhaustive]`.
        _ => TlsError::Other(format!("rustls: unmapped error {e:?}")),
    }
}
