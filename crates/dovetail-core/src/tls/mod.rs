//! The TLS surface every component in this workspace is written against.
//!
//! One backend implements it: `rustls`, pure Rust and auditable. Nothing above
//! this module knows which stack is active, because there is only one —
//! a benchmark drawn from above this layer measures the record path, not a
//! choice of stacks.
//!
//! Selecting rustls is not a cargo feature and not a runtime switch: it is the
//! only stack linked, so a missing backend cannot become a silent fallback to
//! plaintext — the failure mode a feature flag exists to prevent, and one that
//! no test would catch because a test asserting "no plaintext" would need
//! a plaintext path to assert against.
//!
//! # What the interface deliberately does not have
//!
//! No method whose answer could differ per stack. [`TlsError`] carries no
//! backend-specific detail, and [`TlsProvider::suites`] is read from rustls
//! rather than declared here, because a hand-written list would drift from the
//! stack it describes and a drifted list makes every comparison drawn from it
//! meaningless.

use std::fmt;

/// The transport rustls is written against.
///
/// A blanket impl, because rustls takes any
/// `Read + Write`: anything that can carry bytes can carry TLS over them, and
/// making this a real trait would only add a bound the stack never needs.
pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// Everything needed to open a client session, in terms neither stack knows.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// The name sent as SNI and checked against the certificate.
    pub server_name: String,
    /// ALPN protocols to offer, in preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Extra trust anchors, DER-encoded.
    ///
    /// rustls also loads the platform's default roots; these are added on
    /// top, so a caller pinning its own CA does not lose the system ones.
    pub roots: Vec<Vec<u8>>,
}

/// What a component needs from a TLS stack.
///
/// Deliberately narrow, and the providers themselves implement `Read + Write`, so
/// a caller above this module moves encrypted bytes without knowing which stack
/// produced them.
pub trait TlsProvider: std::io::Read + std::io::Write {
    /// The stack's own name, for reports and benchmarks.
    fn name() -> &'static str
    where
        Self: Sized;

    /// The cipher suites this build will negotiate, in preference order, as the
    /// backend itself reports them.
    ///
    /// Read from the stack rather than written down here: a list in this file
    /// would be a claim about the stack rather than a report of it, and would go
    /// stale silently the next time the stack changed its defaults.
    fn suites(&self) -> Vec<String>;

    /// Drive the handshake to completion, doing I/O on the transport.
    fn handshake(&mut self) -> Result<(), TlsError>;

    /// The ALPN protocol the peer selected, if any.
    fn alpn(&self) -> Option<&[u8]>;
}

/// A backend could not complete a handshake or a record operation.
///
/// The variants carry no backend-specific detail on purpose: classification is
/// what a caller branches on, and mapping is the adapter's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The peer did not complete the handshake in time.
    Timeout,
    /// The peer's certificate or signature did not verify.
    BadCertificate,
    /// The peer closed, or the record was truncated.
    Closed,
    /// The peer offered nothing this build will negotiate.
    NoSharedCipher,
    /// The backend reported a failure that does not map to the above.
    Other(String),
}

impl TlsError {
    /// Attach context while keeping the variant.
    ///
    /// A backend that reports a certificate failure but not which anchor rejected
    /// it leaves the caller unable to say anything useful. This keeps the
    /// classification — which is what a caller branches on — and adds the detail
    /// that the backend-neutral type deliberately has nowhere else to put.
    #[must_use]
    pub fn with_detail(self, detail: impl Into<String>) -> Self {
        match self {
            Self::Timeout => Self::Other(format!("timeout: {}", detail.into())),
            Self::BadCertificate => Self::Other(format!("bad certificate: {}", detail.into())),
            Self::Closed => Self::Other(format!("closed: {}", detail.into())),
            Self::NoSharedCipher => Self::Other(format!("no shared cipher: {}", detail.into())),
            Self::Other(why) => Self::Other(format!("{why}: {}", detail.into())),
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("handshake timed out"),
            Self::BadCertificate => f.write_str("certificate did not verify"),
            Self::Closed => f.write_str("connection closed by peer"),
            Self::NoSharedCipher => f.write_str("no shared cipher suite"),
            Self::Other(why) => write!(f, "backend error: {why}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// So a `TlsError` raised while driving a handshake can propagate out of the
/// `Read` and `Write` impls, which are required to return `std::io::Error`.
///
/// The mapping is lossy in one direction and that is deliberate: a caller reading
/// through a provider sees an `io::Error`, and [`TlsError`] is recovered by
/// downcasting. Anything else would mean inventing an `io::ErrorKind` per
/// variant, and inventing one is how a caller ends up matching on a kind the
/// backend never actually reported.
impl From<TlsError> for std::io::Error {
    fn from(e: TlsError) -> Self {
        std::io::Error::other(e)
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout,
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::Closed,
            _ => Self::Other(e.to_string()),
        }
    }
}

mod rustls_backend;
pub use rustls_backend::RustlsProvider;

/// Open a client session over `io`.
///
/// # Errors
///
/// Anything [`TlsProvider::handshake`] could return, plus a configuration the
/// stack rejected before any I/O.
pub fn connect<S: Stream>(cfg: &TlsConfig, io: S) -> Result<impl TlsProvider + use<S>, TlsError> {
    RustlsProvider::connect(cfg, io)
}

/// The stack compiled into this build.
///
/// Used by benchmarks and reports to name the stack a number came from, so a
/// measurement can never be read without knowing what produced it.
pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}
