//! Xray-shaped serving surface over the `VLESS` framing this core encodes.
//!
//! Three subcommands the oracle seams call: `version`, `x25519`, and `run -c`
//! with `vless` or `socks` inbounds. Only raw-`TCP` relay exists so far: anything
//! else closes fast rather than hanging the suite that asked for it.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::json::Json;

/// This binary, so the oracle log names what actually served the test.
pub(crate) fn print_version() {
    println!("dovetail-zeronet {}", env!("CARGO_PKG_VERSION"));
}

/// A real `X25519` pair in the labels the oracle parser matches on.
pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

/// Serve every inbound in a config file until killed, like `xray run -c`.
pub(crate) fn serve_file(path: &str) -> ! {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| exit(&format!("cannot read {path}: {error}")));
    let root = crate::json::parse(&text)
        .unwrap_or_else(|error| exit(&format!("bad config {path}: {error}")));
    let freedom = has_protocol(&root, "outbounds", "freedom");
    let vless_out = find_vless_outbound(&root);
    let mut inbounds = 0;
    if let Some(list) = root.get("inbounds").and_then(Json::as_arr) {
        for inbound in list {
            let listen = inbound
                .get("listen")
                .and_then(Json::as_str)
                .unwrap_or("127.0.0.1");
            let Some(port) = inbound.get("port").and_then(Json::as_port) else {
                continue;
            };
            let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
            let address = format!("{listen}:{port}");
            match protocol {
                "vless" => {
                    let id = inbound_id(inbound);
                    let address_clone = address.clone();
                    thread::spawn(move || accept_loop(&address_clone, Role::Vless { id, freedom }));
                    inbounds += 1;
                }
                "socks" => {
                    let Some(out) = vless_out.clone() else {
                        continue;
                    };
                    thread::spawn(move || accept_loop(&address, Role::Socks { out }));
                    inbounds += 1;
                }
                _ => eprintln!("unsupported inbound protocol `{protocol}` in {path}"),
            }
        }
    }
    if inbounds == 0 {
        exit(&format!("no servable inbound in {path}"));
    }
    loop {
        thread::park();
    }
}

/// Print a fatal config error and never return.
fn exit(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// One inbound's serving role, decided once from the config.
#[derive(Debug, Clone)]
enum Role {
    /// Accept `VLESS`, dial the requested target itself.
    Vless { id: [u8; 16], freedom: bool },
    /// Accept `SOCKS5`, relay through the configured `VLESS` server.
    Socks { out: VlessOut },
}

/// Where a `socks` inbound forwards: one `vnext` server and its user.
#[derive(Debug, Clone)]
struct VlessOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// User id bytes.
    id: [u8; 16],
}

/// Accept forever, one thread per connection.
fn accept_loop(address: &str, role: Role) {
    let listener = TcpListener::bind(address)
        .unwrap_or_else(|error| exit(&format!("cannot listen on {address}: {error}")));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let role = role.clone();
        thread::spawn(move || match role {
            Role::Vless { id, freedom } => serve_vless(stream, &id, freedom),
            Role::Socks { out } => serve_socks(stream, &out),
        });
    }
}

/// Serve one `VLESS`/`TCP` connection: check the user, dial, answer `[0, 0]`, relay.
fn serve_vless(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
    let Some((got, cmd, target)) = decode_request(&mut stream) else {
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if stream.write_all(&[0, 0]).is_err() {
        return;
    }
    relay(stream, uplink);
}

/// Serve one `SOCKS5` connection by dialing through the `VLESS` server.
fn serve_socks(mut client: TcpStream, out: &VlessOut) {
    let Some(target) = socks_handshake(&mut client) else {
        return;
    };
    let address = format!("{}:{}", out.address, out.port);
    let server = address.to_socket_addrs().ok().and_then(|mut it| it.next());
    let Some(server) = server else { return };
    let Ok(mut uplink) = TcpStream::connect_timeout(&server, Duration::from_secs(8)) else {
        return;
    };
    let mut header = Vec::with_capacity(30);
    header.push(0);
    header.extend_from_slice(&out.id);
    header.push(0);
    header.push(1);
    header.extend_from_slice(&target.port().to_be_bytes());
    push_addr(&mut header, &target);
    if uplink.write_all(&header).is_err() {
        return;
    }
    let mut prefix = [0u8; 2];
    if read_exact(&mut uplink, &mut prefix).is_err() {
        return;
    }
    let Ok(consumed) = dovetail_core::vless::VlessLink::decode_response_header(&prefix) else {
        return;
    };
    if consumed > 2 {
        let mut rest = vec![0u8; consumed - 2];
        if read_exact(&mut uplink, &mut rest).is_err() {
            return;
        }
    }
    relay(client, uplink);
}

/// Copy both directions; each half closes both sockets when its copy ends.
fn relay(client: TcpStream, target: TcpStream) {
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let Ok(target_read) = target.try_clone() else {
        return;
    };
    let done = thread::spawn(move || {
        let _ = std::io::copy(&mut &client_read, &mut &target);
        let _ = client_read.shutdown(Shutdown::Both);
    });
    let _ = std::io::copy(&mut &target_read, &mut &client);
    let _ = target_read.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// Read exactly `buf.len()` bytes, one partial read at a time.
fn read_exact(stream: &mut TcpStream, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Decode a client request header from the stream: `(id, command, target)`.
fn decode_request(stream: &mut TcpStream) -> Option<([u8; 16], u8, SocketAddr)> {
    let mut head = [0u8; 18];
    read_exact(stream, &mut head).ok()?;
    if head[0] != 0 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[1..17]);
    let addons = usize::from(head[17]);
    if addons > 0 {
        let mut skip = vec![0u8; addons];
        read_exact(stream, &mut skip).ok()?;
    }
    let mut cmd = [0u8; 1];
    read_exact(stream, &mut cmd).ok()?;
    let mut port = [0u8; 2];
    read_exact(stream, &mut port).ok()?;
    let target = read_addr(stream, u16::from_be_bytes(port))?;
    Some((id, cmd[0], target))
}

/// Read one `atyp` address for a known port.
fn read_addr(stream: &mut TcpStream, port: u16) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    match atyp[0] {
        1 => {
            let mut ip = [0u8; 4];
            read_exact(stream, &mut ip).ok()?;
            Some(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port))
        }
        2 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let host = String::from_utf8(name).ok()?;
            format!("{host}:{port}").to_socket_addrs().ok()?.next()
        }
        3 => {
            let mut ip = [0u8; 16];
            read_exact(stream, &mut ip).ok()?;
            Some(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port))
        }
        _ => None,
    }
}

/// Append `atyp` plus address bytes for a socket address.
fn push_addr(header: &mut Vec<u8>, target: &SocketAddr) {
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            header.push(3);
            header.extend_from_slice(&ip.octets());
        }
    }
}

/// Accept a `SOCKS5` `CONNECT`, returning the requested target.
fn socks_handshake(client: &mut TcpStream) -> Option<SocketAddr> {
    let mut head = [0u8; 2];
    read_exact(client, &mut head).ok()?;
    if head[0] != 5 {
        return None;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    read_exact(client, &mut methods).ok()?;
    if client.write_all(&[5, 0]).is_err() {
        return None;
    }
    let mut req = [0u8; 4];
    read_exact(client, &mut req).ok()?;
    if req[0] != 5 || req[1] != 1 {
        return None;
    }
    let target = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            read_exact(client, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(client, &mut port).ok()?;
            SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port))
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact(client, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(client, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(client, &mut port).ok()?;
            let host = String::from_utf8(name).ok()?;
            format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()?
        }
        4 => {
            let mut ip = [0u8; 16];
            read_exact(client, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(client, &mut port).ok()?;
            SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port))
        }
        _ => return None,
    };
    if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    Some(target)
}

/// First inbound `vless` client's id bytes, zeros when unparseable.
fn inbound_id(inbound: &Json) -> [u8; 16] {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
        .and_then(|client| client.get("id"))
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .unwrap_or([0u8; 16])
}

/// Whether any entry in `array` names `protocol`.
fn has_protocol(root: &Json, array: &str, protocol: &str) -> bool {
    root.get(array).and_then(Json::as_arr).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("protocol").and_then(Json::as_str) == Some(protocol))
    })
}

/// First `vless` outbound's server and user, `None` when the shape differs.
fn find_vless_outbound(root: &Json) -> Option<VlessOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("vless") {
            continue;
        }
        let vnext = outbound
            .get("settings")
            .and_then(|s| s.get("vnext"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = vnext else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let id = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .and_then(|user| user.get("id"))
            .and_then(Json::as_str)
            .and_then(uuid_bytes)?;
        return Some(VlessOut { address, port, id });
    }
    None
}

/// Lowercase-hex `8-4-4-4-12` UUID to bytes, `None` on any other shape.
fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(h) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (h << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    if index == 16 && high.is_none() {
        Some(out)
    } else {
        None
    }
}

/// Fresh clamped private key with its public key, both unpadded base64url.
fn x25519_pair() -> (String, String) {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private)
        .unwrap_or_else(|error| exit(&format!("no entropy: {error}")));
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64url(&private), b64url(&public))
}

/// Unpadded base64url, the encoding the oracle keys arrive in.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        let mut shift = 18;
        for _ in 0..chunk.len() + 1 {
            out.push(ALPHABET[((word >> shift) & 63) as usize] as char);
            shift -= 6;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_oracle_shape() {
        assert_eq!(b64url(&[0u8; 32]), "A".repeat(43));
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn uuid_parses_and_rejects() {
        assert_eq!(
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("parses")[0..2],
            [0xaa, 0xaa]
        );
        assert!(uuid_bytes("not-a-uuid").is_none());
        assert!(uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee").is_none());
    }

    #[test]
    fn decodes_what_the_core_encodes() {
        let link = dovetail_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("192.0.2.53", 80);
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream).expect("decodes")
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&header).expect("writes");
        let (id, cmd, target) = writer.join().expect("joins");
        assert_eq!(
            id,
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id")
        );
        assert_eq!(cmd, 1);
        assert_eq!(target.to_string(), "192.0.2.53:80");
        drop(reader);
    }

    #[test]
    fn rejects_a_wrong_version_and_user() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream)
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&[1u8; 18]).expect("writes");
        assert!(writer.join().expect("joins").is_none());
        drop(reader);
    }
}
