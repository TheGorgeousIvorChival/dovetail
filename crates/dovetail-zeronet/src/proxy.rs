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
    let outbound = find_outbound(&root);
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
                    let carrier = inbound_carrier(inbound);
                    if !vless_security_supported(stream_security(inbound)) {
                        eprintln!(
                            "unsupported vless security `{}` in {path}: serves raw TCP only",
                            stream_security(inbound)
                        );
                        continue;
                    }
                    let address_clone = address.clone();
                    let role = Role::Vless {
                        id,
                        carrier,
                        freedom,
                    };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "trojan" => {
                    let password = inbound_password(inbound);
                    let address_clone = address.clone();
                    let role = Role::Trojan { password, freedom };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "vmess" => {
                    let id = inbound_id(inbound);
                    let address_clone = address.clone();
                    let role = Role::Vmess { id, freedom };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "shadowsocks" => {
                    let password = inbound_ss_password(inbound);
                    let method = inbound_method(inbound);
                    let address_clone = address.clone();
                    let role = Role::Shadowsocks {
                        password,
                        method,
                        freedom,
                    };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "socks" => {
                    let Some(out) = outbound.clone() else {
                        continue;
                    };
                    let role = Role::Socks { out };
                    thread::spawn(move || accept_loop(&address, &role));
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
    Vless {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    /// Accept `trojan`, dial the requested target itself.
    Trojan { password: String, freedom: bool },
    /// Accept `VMess`, dial the requested target itself.
    Vmess { id: [u8; 16], freedom: bool },
    /// Accept `shadowsocks`, dial the requested target itself.
    Shadowsocks {
        password: String,
        method: String,
        freedom: bool,
    },
    /// Accept `SOCKS5`, relay through the configured upstream server.
    Socks { out: Outbound },
}

/// Where a `socks` inbound forwards: one upstream server and its credential.
#[derive(Debug, Clone)]
enum Outbound {
    /// A `vnext` server and its user id bytes.
    Vless(VlessOut),
    /// A `trojan` server and its password.
    Trojan(TrojanOut),
    /// A `vmess` server, user id and cipher.
    Vmess(VmessOut),
    /// A `shadowsocks` server, cipher, and password.
    Shadowsocks(ShadowsocksOut),
}

/// A `vless` upstream server.
#[derive(Debug, Clone)]
struct VlessOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// User id bytes.
    id: [u8; 16],
    /// Carrier around unchanged `VLESS` bytes, raw `TCP` when unnamed.
    carrier: Carrier,
    /// `Host` header as written, falling back to the server address.
    host: String,
}

/// Framing around unchanged `VLESS` bytes, read once from `streamSettings`.
#[derive(Debug, Clone)]
enum Carrier {
    /// Raw `TCP`, the default when nothing else is named.
    Raw,
    /// `WebSocket` upgrade at this path.
    Ws { path: String },
    /// `HTTPUpgrade` at this path, raw bytes after the `101`.
    HttpUpgrade { path: String },
    /// `gRPC` tunnel at this service path.
    Grpc { path: String },
}

/// A `vmess` upstream server.
#[derive(Debug, Clone)]
struct VmessOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// User id bytes.
    id: [u8; 16],
    /// Data cipher as written.
    cipher: crate::vmess::Cipher,
}

/// A `trojan` upstream server.
#[derive(Debug, Clone)]
struct TrojanOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// Password as written.
    password: String,
}

/// A `shadowsocks` upstream server.
#[derive(Debug, Clone)]
struct ShadowsocksOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// Cipher name as written.
    method: String,
    /// Password as written.
    password: String,
}

/// Accept forever, one thread per connection.
fn accept_loop(address: &str, role: &Role) {
    let listener = TcpListener::bind(address)
        .unwrap_or_else(|error| exit(&format!("cannot listen on {address}: {error}")));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let role = role.clone();
        thread::spawn(move || match role {
            Role::Vless {
                id,
                carrier,
                freedom,
            } => serve_vless(stream, &id, &carrier, freedom),
            Role::Trojan { password, freedom } => serve_trojan(stream, &password, freedom),
            Role::Vmess { id, freedom } => crate::vmess::serve(stream, &id, freedom),
            Role::Shadowsocks {
                password,
                method,
                freedom,
            } => crate::shadowsocks::serve(stream, &password, &method, freedom),
            Role::Socks { out } => serve_socks(stream, &out),
        });
    }
}

/// Serve one `VLESS` connection: raw `TCP` by default, framed when named.
fn serve_vless(stream: TcpStream, id: &[u8; 16], carrier: &Carrier, freedom: bool) {
    match carrier {
        Carrier::Raw => serve_vless_raw(stream, id, freedom),
        Carrier::Ws { path } => {
            let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
                return;
            };
            let Some((got, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::ws::relay(reader, &writer, &uplink);
        }
        Carrier::HttpUpgrade { path } => {
            let Some((mut reader, mut write)) = crate::httpupgrade::accept(stream, path) else {
                return;
            };
            let Some((got, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
                return;
            };
            if write.write_all(&[0, 0]).is_err() {
                return;
            }
            crate::httpupgrade::relay(reader, &write, &uplink);
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
                return;
            };
            let Some((got, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::grpc::relay(reader, &writer, &uplink);
        }
    }
}

/// Serve one `VLESS`/`TCP` connection: check the user, dial, answer `[0, 0]`, relay.
fn serve_vless_raw(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
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
    relay(&stream, &uplink);
}

/// Dial one `vless` upstream for a `SOCKS` target, over whatever carrier is named.
fn dial_vless(client: &TcpStream, mut uplink: TcpStream, vless: &VlessOut, target: &SocketAddr) {
    let mut header = Vec::with_capacity(30);
    header.push(0);
    header.extend_from_slice(&vless.id);
    header.push(0);
    header.push(1);
    header.extend_from_slice(&target.port().to_be_bytes());
    push_addr(&mut header, target, 3);
    match &vless.carrier {
        Carrier::Ws { path } => {
            let Some((mut reader, writer)) = crate::ws::connect(uplink, &vless.host, path) else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::ws::relay(reader, &writer, client);
        }
        Carrier::HttpUpgrade { path } => {
            let Some((mut reader, mut write)) =
                crate::httpupgrade::connect(uplink, &vless.host, path)
            else {
                return;
            };
            if write.write_all(&header).is_err() {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::httpupgrade::relay(reader, &write, client);
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = crate::grpc::connect(uplink, &vless.host, path) else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::grpc::relay(reader, &writer, client);
        }
        Carrier::Raw => {
            if uplink.write_all(&header).is_err() {
                return;
            }
            if read_vless_response(&mut uplink).is_none() {
                return;
            }
            relay(client, &uplink);
        }
    }
}

/// Serve one `trojan` connection: check the password, dial, relay with no reply.
fn serve_trojan(mut stream: TcpStream, password: &str, freedom: bool) {
    let Some((cmd, target)) = decode_trojan_request(&mut stream, password) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    relay(&stream, &uplink);
}

/// Serve one `SOCKS5` connection by dialing through the upstream server.
fn serve_socks(mut client: TcpStream, out: &Outbound) {
    let Some(target) = socks_handshake(&mut client) else {
        return;
    };
    let (address, port) = match out {
        Outbound::Vless(vless) => (vless.address.clone(), vless.port),
        Outbound::Vmess(vmess) => (vmess.address.clone(), vmess.port),
        Outbound::Trojan(trojan) => (trojan.address.clone(), trojan.port),
        Outbound::Shadowsocks(shadowsocks) => (shadowsocks.address.clone(), shadowsocks.port),
    };
    let dial = format!("{address}:{port}");
    let server = dial.to_socket_addrs().ok().and_then(|mut it| it.next());
    let Some(server) = server else { return };
    let Ok(mut uplink) = TcpStream::connect_timeout(&server, Duration::from_secs(8)) else {
        return;
    };
    match out {
        Outbound::Vless(vless) => dial_vless(&client, uplink, vless, &target),
        Outbound::Vmess(vmess) => {
            let Some((send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_handshake(&mut uplink, &vmess.id, vmess.cipher, &target)
            else {
                return;
            };
            crate::vmess::pump_relay(
                &client,
                &uplink,
                send,
                recv,
                Some((response_key, response_iv, auth)),
            );
        }
        Outbound::Trojan(trojan) => {
            let mut header = Vec::with_capacity(70);
            header.extend_from_slice(&trojan_key(&trojan.password));
            header.extend_from_slice(b"\r\n");
            header.push(1);
            push_addr(&mut header, &target, 4);
            header.extend_from_slice(&target.port().to_be_bytes());
            header.extend_from_slice(b"\r\n");
            if uplink.write_all(&header).is_err() {
                return;
            }
            relay(&client, &uplink);
        }
        Outbound::Shadowsocks(shadowsocks) => {
            let Some((send, recv)) = crate::shadowsocks::client_send_handshake(
                &mut uplink,
                &shadowsocks.password,
                &shadowsocks.method,
                &target,
            ) else {
                return;
            };
            crate::shadowsocks::pump_relay(&client, &uplink, send, recv);
        }
    }
}

/// Copy both directions; each half closes both sockets when its copy ends.
fn relay(client: &TcpStream, target: &TcpStream) {
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let Ok(target_read) = target.try_clone() else {
        return;
    };
    let Ok(target_write) = target.try_clone() else {
        return;
    };
    let Ok(client_write) = client.try_clone() else {
        return;
    };
    let mut client_read = client_read;
    let mut target_write = target_write;
    let mut target_read = target_read;
    let mut client_write = client_write;
    let done = thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut target_write);
        let _ = client_read.shutdown(Shutdown::Both);
        let _ = target_write.shutdown(Shutdown::Both);
    });
    let _ = std::io::copy(&mut target_read, &mut client_write);
    let _ = target_read.shutdown(Shutdown::Both);
    let _ = client_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// Read exactly `buf.len()` bytes, one partial read at a time.
pub(crate) fn read_exact(stream: &mut dyn Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Read one `VLESS` response header off the stream, `None` on any mismatch.
fn read_vless_response(stream: &mut dyn Read) -> Option<()> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let consumed = dovetail_core::vless::VlessLink::decode_response_header(&prefix).ok()?;
    if consumed > 2 {
        let mut rest = vec![0u8; consumed - 2];
        read_exact(stream, &mut rest).ok()?;
    }
    Some(())
}

/// Decode a client request header from the stream: `(id, command, target)`.
fn decode_request(stream: &mut dyn Read) -> Option<([u8; 16], u8, SocketAddr)> {
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

/// Decode a `trojan` request: key, `CRLF`, command, `SOCKS`-order address, `CRLF`.
fn decode_trojan_request(stream: &mut TcpStream, password: &str) -> Option<(u8, SocketAddr)> {
    let mut key = [0u8; 56];
    read_exact(stream, &mut key).ok()?;
    if key != trojan_key(password) {
        return None;
    }
    let mut crlf = [0u8; 2];
    read_exact(stream, &mut crlf).ok()?;
    if crlf != *b"\r\n" {
        return None;
    }
    let mut cmd = [0u8; 1];
    read_exact(stream, &mut cmd).ok()?;
    let target = read_socks_addr(stream)?;
    read_exact(stream, &mut crlf).ok()?;
    if crlf != *b"\r\n" {
        return None;
    }
    Some((cmd[0], target))
}

/// Read one `VLESS` address (`1`/`2`/`3`) for a known port.
fn read_addr(stream: &mut dyn Read, port: u16) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    if atyp[0] == 1 {
        let mut ip = [0u8; 4];
        read_exact(stream, &mut ip).ok()?;
        return Some(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port));
    }
    if atyp[0] == 3 {
        let mut ip = [0u8; 16];
        read_exact(stream, &mut ip).ok()?;
        return Some(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port));
    }
    if atyp[0] != 2 {
        return None;
    }
    let mut len = [0u8; 1];
    read_exact(stream, &mut len).ok()?;
    let mut name = vec![0u8; usize::from(len[0])];
    read_exact(stream, &mut name).ok()?;
    let host = String::from_utf8(name).ok()?;
    format!("{host}:{port}").to_socket_addrs().ok()?.next()
}

/// Append `atyp` plus address bytes for a socket address; `v6` tags `IPv6`.
pub(crate) fn push_addr(header: &mut Vec<u8>, target: &SocketAddr, v6: u8) {
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            header.push(v6);
            header.extend_from_slice(&ip.octets());
        }
    }
}

/// Hex digits for password hashing.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex `SHA224` of a password: the 56-byte `trojan` key.
fn trojan_key(password: &str) -> [u8; 56] {
    use sha2::Digest as _;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, byte) in digest.iter().enumerate() {
        out[2 * i] = HEX[(byte >> 4) as usize];
        out[2 * i + 1] = HEX[(byte & 0x0F) as usize];
    }
    out
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
    let target = read_socks_addr_rest(client, req[3])?;
    if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    Some(target)
}

/// Read a `SOCKS`-order address (`atyp`, address, port) from the stream.
fn read_socks_addr(stream: &mut TcpStream) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    read_socks_addr_rest(stream, atyp[0])
}

/// Read the address and port after a `SOCKS`-order `atyp` byte.
fn read_socks_addr_rest(stream: &mut TcpStream, atyp: u8) -> Option<SocketAddr> {
    match atyp {
        1 => {
            let mut ip = [0u8; 4];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V4(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            let host = String::from_utf8(name).ok()?;
            format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()
        }
        4 => {
            let mut ip = [0u8; 16];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V6(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        _ => None,
    }
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

/// First inbound cipher name, empty when unparseable.
fn inbound_method(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("method"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Inbound `shadowsocks` password, sitting beside `method`, empty when absent.
pub(crate) fn inbound_ss_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// First inbound `trojan` client's password, empty when unparseable.
fn inbound_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
        .and_then(|client| client.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// First non-`freedom` outbound in `vless`, `vmess`, `trojan`, `shadowsocks` order.
fn find_outbound(root: &Json) -> Option<Outbound> {
    if let Some(vless) = find_vless_outbound(root) {
        return Some(Outbound::Vless(vless));
    }
    if let Some(vmess) = find_vmess_outbound(root) {
        return Some(Outbound::Vmess(vmess));
    }
    if let Some(trojan) = find_trojan_outbound(root) {
        return Some(Outbound::Trojan(trojan));
    }
    find_shadowsocks_outbound(root).map(Outbound::Shadowsocks)
}

/// First `trojan` outbound's server and password, `None` when the shape differs.
fn find_trojan_outbound(root: &Json) -> Option<TrojanOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("trojan") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let password = server.get("password").and_then(Json::as_str)?.to_owned();
        return Some(TrojanOut {
            address,
            port,
            password,
        });
    }
    None
}

/// First `shadowsocks` outbound's server, cipher and password, `None` otherwise.
fn find_shadowsocks_outbound(root: &Json) -> Option<ShadowsocksOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("shadowsocks") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let method = server.get("method").and_then(Json::as_str)?.to_owned();
        let password = server.get("password").and_then(Json::as_str)?.to_owned();
        return Some(ShadowsocksOut {
            address,
            port,
            method,
            password,
        });
    }
    None
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
        if !vless_security_supported(stream_security(outbound)) {
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
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(VlessOut {
            address,
            port,
            id,
            carrier,
            host,
        });
    }
    None
}

/// First `vmess` outbound's server, user and cipher, `None` otherwise.
fn find_vmess_outbound(root: &Json) -> Option<VmessOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("vmess") {
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
        let user = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())?;
        let id = user.get("id").and_then(Json::as_str).and_then(uuid_bytes)?;
        let cipher = crate::vmess::Cipher::parse(
            user.get("security")
                .and_then(Json::as_str)
                .unwrap_or("auto"),
        );
        return Some(VmessOut {
            address,
            port,
            id,
            cipher,
        });
    }
    None
}

/// Carrier from a `streamSettings` block, raw `TCP` when nothing is named.
fn stream_carrier(settings: Option<&Json>) -> Carrier {
    match settings
        .and_then(|s| s.get("network"))
        .and_then(Json::as_str)
    {
        Some("ws") => Carrier::Ws {
            path: sub_path(settings, "wsSettings"),
        },
        Some("httpupgrade") => Carrier::HttpUpgrade {
            path: sub_path(settings, "httpupgradeSettings"),
        },
        Some("grpc") => Carrier::Grpc {
            path: grpc_path(settings),
        },
        _ => Carrier::Raw,
    }
}

/// Upgrade path from a settings block, `/` when unnamed.
fn sub_path(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("path"))
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_owned()
}

/// `gRPC` service path from `serviceName`, `/<service>/Tun` like every peer.
fn grpc_path(settings: Option<&Json>) -> String {
    let service = settings
        .and_then(|s| s.get("grpcSettings"))
        .and_then(|s| s.get("serviceName"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .trim();
    if service.is_empty() {
        return "/Tun".to_owned();
    }
    if service.starts_with('/') {
        return service.to_owned();
    }
    format!("/{}/Tun", service.trim_matches('/'))
}

/// Carrier plus `Host` from an outbound's `streamSettings`, raw by default.
fn outbound_carrier(outbound: &Json, address: &str) -> (Carrier, String) {
    let settings = outbound.get("streamSettings");
    let carrier = stream_carrier(settings);
    let key = match &carrier {
        Carrier::Ws { .. } => "wsSettings",
        Carrier::HttpUpgrade { .. } => "httpupgradeSettings",
        Carrier::Grpc { .. } => "grpcSettings",
        Carrier::Raw => "",
    };
    let host = settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str)
        .unwrap_or(address)
        .to_owned();
    (carrier, host)
}

/// Carrier from an inbound's `streamSettings`, raw `TCP` when unnamed.
fn inbound_carrier(inbound: &Json) -> Carrier {
    stream_carrier(inbound.get("streamSettings"))
}

/// Outer security of an inbound or outbound, `""` when unnamed.
fn stream_security(node: &Json) -> &str {
    node.get("streamSettings")
        .and_then(|s| s.get("security"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

/// Whether this build serves or dials that security over raw `TCP`.
fn vless_security_supported(sec: &str) -> bool {
    sec.is_empty() || sec == "none"
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
    private[0] &= 0xF8;
    private[31] &= 0x7F;
    private[31] |= 0x40;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64url(&private), b64url(&public))
}

/// Unpadded base64url, the encoding the oracle keys arrive in.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        let mut shift = 18;
        for _ in 0..=chunk.len() {
            out.push(ALPHABET[((word >> shift) & 0x3F) as usize] as char);
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
    fn trojan_key_is_sha224_hex() {
        assert_eq!(
            trojan_key("an-example-shared-password"),
            *b"73317e3bf920a459723610d27b71cadc07061d8f0d8587e041944896"
        );
    }

    #[test]
    fn trojan_relay_round_trips_and_refuses_strangers() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = echo.accept().expect("accepts");
            relay(&stream, &stream);
        });
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || serve_trojan(stream, "an-example-shared-password", true));
            }
        });
        let mut good = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("an-example-shared-password"));
        header.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01");
        header.extend_from_slice(&echo_port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        good.write_all(&header).expect("writes");
        good.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        good.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        let mut bad = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        bad.write_all(&[0u8; 64]).expect("writes");
        let mut closed = [0u8; 1];
        assert!(bad.read(&mut closed).is_err() || closed == [0]);
        drop(good);
        drop(bad);
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

    #[test]
    fn vless_security_gate_keeps_plain_and_refuses_reality() {
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let none =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "none"}}"#)
                .expect("parses");
        let reality =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "reality"}}"#)
                .expect("parses");
        let tls =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "tls"}}"#)
                .expect("parses");
        assert!(vless_security_supported(stream_security(&plain)));
        assert!(vless_security_supported(stream_security(&none)));
        assert!(!vless_security_supported(stream_security(&reality)));
        assert!(!vless_security_supported(stream_security(&tls)));
    }

    #[test]
    fn vless_outbound_with_reality_security_is_skipped() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality"}}]}"#,
        )
        .expect("parses");
        assert!(find_vless_outbound(&root).is_none());
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
            "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        assert!(find_vless_outbound(&root).is_some());
    }
}
