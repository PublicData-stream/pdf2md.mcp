use crate::{
    config::{Source, Step},
    error::{LoadError, Result},
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    origins: HashSet<String>,
    #[cfg(test)]
    fixture: Option<SocketAddr>,
}

pub fn origin(value: &str) -> Result<String> {
    let u = Url::parse(value).map_err(|_| denied())?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port_or_known_default() != Some(443)
        || u.host_str().is_none()
    {
        return Err(denied());
    }
    Ok(u.origin().ascii_serialization())
}

pub fn sanitized_url(value: &str) -> Option<String> {
    let mut u = Url::parse(value).ok()?;
    u.set_username("").ok()?;
    u.set_password(None).ok()?;
    u.set_query(None);
    u.set_fragment(None);
    // Signed URLs may carry credentials in path segments as well as queries.
    u.set_path("/");
    Some(u.to_string())
}

fn denied() -> LoadError {
    LoadError::new(
        "network_policy",
        "destination is not an approved public HTTPS origin on port 443",
    )
}

impl NetworkPolicy {
    pub fn for_source(source: &Source) -> Result<Self> {
        let mut origins = HashSet::new();
        origins.insert(origin(&source.url)?);
        for item in &source.allowed_origins {
            origins.insert(origin(item)?);
        }
        let p = Self {
            origins,
            #[cfg(test)]
            fixture: None,
        };
        p.validate_url(&source.url)?;
        for h in &source.headers {
            p.validate_url(&h.origin)?;
        }
        for c in &source.cookies {
            p.validate_url(&c.origin)?;
        }
        for s in &source.steps {
            match s {
                Step::Navigate { url } => {
                    p.validate_url(url)?;
                }
                Step::Fill { origin, .. } => {
                    p.validate_url(origin)?;
                }
                _ => {}
            }
        }
        Ok(p)
    }
    pub fn origins(&self) -> Vec<String> {
        let mut v: Vec<_> = self.origins.iter().cloned().collect();
        v.sort();
        v
    }
    pub fn validate_url(&self, value: &str) -> Result<Url> {
        let o = origin(value)?;
        if !self.origins.contains(&o) {
            return Err(denied());
        }
        let u = Url::parse(value).map_err(|_| denied())?;
        match u.host() {
            Some(Host::Ipv4(ip)) if !is_public(IpAddr::V4(ip)) => return Err(denied()),
            Some(Host::Ipv6(ip)) if !is_public(IpAddr::V6(ip)) => return Err(denied()),
            _ => {}
        }
        Ok(u)
    }
    pub async fn resolve(&self, u: &Url) -> Result<Vec<SocketAddr>> {
        self.validate_url(u.as_str())?;
        #[cfg(test)]
        if let Some(addr) = self.fixture {
            return Ok(vec![addr]);
        }
        let addresses: Vec<_> = tokio::net::lookup_host((u.host_str().ok_or_else(denied)?, 443))
            .await
            .map_err(|_| LoadError::transient("dns_failed", "destination DNS resolution failed"))?
            .collect();
        if addresses.is_empty() || addresses.iter().any(|a| !is_public(a.ip())) {
            return Err(denied());
        }
        Ok(addresses)
    }
    #[cfg(test)]
    pub(crate) fn test_fixture(host: &str, socket: SocketAddr) -> Self {
        Self {
            origins: HashSet::from([format!("https://{host}")]),
            fixture: Some(socket),
        }
    }
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let n = u32::from(ip);
            let ranges: [(u32, u8); 15] = [
                (0x00000000, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ];
            !ranges
                .iter()
                .any(|(base, bits)| n & (u32::MAX << (32 - bits)) == *base)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let seg = ip.segments();
            // Only globally routed unicast; exclude documentation, transition and special allocations.
            (seg[0] & 0xe000) == 0x2000
                && !(seg[0] == 0x2001 && (seg[1] < 0x0200 || seg[1] == 0x0db8))
                && seg[0] != 0x2002
                && !(seg[0] == 0x3fff && seg[1] < 0x1000)
        }
    }
}

/// Application egress proxy. This is not a process or OS network sandbox.
pub struct BrowserProxy {
    pub url: String,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
impl BrowserProxy {
    pub async fn start(policy: NetworkPolicy) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| LoadError::new("proxy_failed", "cannot start browser egress proxy"))?;
        let address = listener
            .local_addr()
            .map_err(|_| LoadError::new("proxy_failed", "cannot inspect browser proxy"))?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let p = Arc::new(policy);
        let task = tokio::spawn(async move {
            let permits = Arc::new(tokio::sync::Semaphore::new(32));
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=stop.cancelled()=>break,
                    Some(_)=connections.join_next(),if !connections.is_empty()=>{},
                    result=listener.accept()=>{
                        let Ok((stream,_))=result else {break};
                        let Ok(permit)=permits.clone().try_acquire_owned() else {drop(stream);continue;};
                        let policy=p.clone();
                        connections.spawn(async move {let _permit=permit; let _=proxy_connection(stream,policy).await;});
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            url: format!("http://{address}"),
            cancel,
            task,
        })
    }
}
impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn proxy_connection(mut incoming: TcpStream, policy: Arc<NetworkPolicy>) -> Result<()> {
    let mut head = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if head.len() >= 8192 {
                return Err(denied());
            }
            let byte = incoming.read_u8().await.map_err(|_| denied())?;
            head.push(byte);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| denied())??;
    let text = std::str::from_utf8(&head).map_err(|_| denied())?;
    let parts: Vec<_> = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    if parts.len() != 3
        || parts[0] != "CONNECT"
        || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[2])
        || !parts[1].ends_with(":443")
        || parts[1].contains(['/', '?', '#', '@', '\\'])
    {
        let _ = incoming
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err(denied());
    }
    let address = format!("https://{}/", parts[1]);
    let result = async {
        let u = policy.validate_url(&address)?;
        let addresses = policy.resolve(&u).await?;
        let mut connected = None;
        for socket in addresses {
            if let Ok(Ok(stream)) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                TcpStream::connect(socket),
            )
            .await
            {
                connected = Some(stream);
                break;
            }
        }
        connected
            .ok_or_else(|| LoadError::transient("connect_failed", "destination connection failed"))
    }
    .await;
    let mut outbound = match result {
        Ok(s) => s,
        Err(e) => {
            let _ = incoming
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(e);
        }
    };
    incoming
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|_| denied())?;
    let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outbound).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forbidden_address_families_are_rejected() {
        for value in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.1.1",
            "192.168.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.1.1.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:7f00:1::",
        ] {
            assert!(!is_public(value.parse().unwrap()), "{value}");
        }
        for value in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(value.parse().unwrap()));
        }
    }
    #[test]
    fn downgrade_credentials_ports_and_unapproved_origins_fail() {
        let p = NetworkPolicy::for_source(&Source::one_off(
            "https://example.com/pdf?token=private".into(),
            crate::config::Mode::Https,
        ))
        .unwrap();
        for value in [
            "http://example.com/",
            "https://example.com:444/",
            "https://private@example.com/",
            "file:///etc/passwd",
            "https://elsewhere.example/",
        ] {
            assert!(p.validate_url(value).is_err());
        }
        assert_eq!(
            sanitized_url("https://user:secret@example.com/a?key=private#fragment").unwrap(),
            "https://example.com/"
        );
    }
    #[tokio::test]
    async fn proxy_rejects_plain_http_and_private_connect() {
        let p = NetworkPolicy::for_source(&Source::one_off(
            "https://example.com/".into(),
            crate::config::Mode::Https,
        ))
        .unwrap();
        let proxy = BrowserProxy::start(p).await.unwrap();
        let u = Url::parse(&proxy.url).unwrap();
        for request in [
            "GET http://example.com/ HTTP/1.1\r\n\r\n",
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:80 HTTP/1.1\r\n\r\n",
        ] {
            let mut socket = TcpStream::connect((u.host_str().unwrap(), u.port().unwrap()))
                .await
                .unwrap();
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut reply = String::new();
            socket.read_to_string(&mut reply).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 403"));
        }
    }

    #[tokio::test]
    async fn dns_resolving_to_loopback_is_rejected() {
        let source = Source::one_off("https://localhost/pdf".into(), crate::config::Mode::Https);
        let policy = NetworkPolicy::for_source(&source).unwrap();
        let error = policy
            .resolve(&policy.validate_url(&source.url).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code, "network_policy");
    }
}
