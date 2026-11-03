use crate::*;
use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Debug)]
pub struct Target {
    pub address: SocketAddr,
    pub origin: Option<String>,
    // A runtime API declaration, not a kernel attestation of the backend.
    pub published: bool,
}

pub(crate) fn metadata_address(ip: IpAddr) -> bool {
    // A listed guest lease must not turn instance credentials into a probe target.
    match ip {
        IpAddr::V4(ip) => ip.octets() == [169, 254, 169, 254],
        IpAddr::V6(ip) => matches!(
            ip.segments(),
            [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254] | [0xfd20, 0xce, 0, 0, 0, 0, 0, 0x254]
        ),
    }
}

pub fn admitted(address: SocketAddr, allowed: &[IpAddr]) -> bool {
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    address.port() > 0
        && (ip.is_loopback() || allowed.contains(&ip))
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !metadata_address(ip)
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub remote: SocketAddr,
    pub local: SocketAddr,
}

pub fn collect(
    snapshot: &mut Snapshot,
    targets: &[Target],
    allowed: &[IpAddr],
    budget: &Budget<'_>,
) -> usize {
    collect_with_connections(snapshot, targets, allowed, budget).0
}

pub fn collect_with_connections(
    snapshot: &mut Snapshot,
    targets: &[Target],
    allowed: &[IpAddr],
    budget: &Budget<'_>,
) -> (usize, Vec<Connection>) {
    collect_paths_with_connections(snapshot, targets, allowed, &default_http_paths(), budget)
}

pub fn collect_paths_with_connections(
    snapshot: &mut Snapshot,
    targets: &[Target],
    allowed: &[IpAddr],
    paths: &[String],
    budget: &Budget<'_>,
) -> (usize, Vec<Connection>) {
    let mut unique = std::collections::BTreeSet::new();
    if paths.is_empty()
        || paths.len() > milvago_discovery_engine::MAX_HTTP_PATHS
        || paths
            .iter()
            .any(|path| !valid_http_path(path) || !unique.insert(path))
    {
        coverage(snapshot, "http", CoverageStatus::Partial, false);
        return (0, vec![]);
    }
    let mut paths = paths.to_vec();
    let length = paths.len();
    paths.rotate_left(snapshot.sequence as usize % length);
    let mut connections = vec![];
    let mut complete = targets.len() <= 128;
    let mut consumed = 0;
    let mut attempts = 0;
    let mut field_budget = FieldBudget::new(snapshot);
    let mut seen = std::collections::BTreeSet::new();
    'targets: for target in targets.iter().take(128) {
        if budget.check().is_err() || attempts >= 128 {
            complete = false;
            break;
        }
        consumed += 1;
        if !seen.insert(target.address) {
            continue;
        }
        if !admitted(target.address, allowed) {
            complete = false;
            continue;
        }
        // A stalled service must leave time for other listeners, including VM
        // endpoints. Keep all paths for a response group on this same deadline.
        let target_budget = budget.child(std::time::Duration::from_secs(if targets.len() > 1 {
            1
        } else {
            30
        }));
        let Ok(timeout) = target_budget.remaining() else {
            complete = false;
            break;
        };
        // Literal IPs, no ambient credentials/proxies, no redirects and only GET.
        let client = match reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
        {
            Ok(client) => client,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let mut endpoint_scheme = None;
        for path in &paths {
            if target_budget.check().is_err() {
                complete = false;
                break;
            }
            let mut response = None;
            for scheme in ["http", "https"] {
                if endpoint_scheme.is_some_and(|selected| selected != scheme) {
                    continue;
                }
                if attempts >= 128 {
                    complete = false;
                    break 'targets;
                }
                let Ok(timeout) = target_budget.remaining() else {
                    complete = false;
                    break;
                };
                attempts += 1;
                if let Ok(found) = client
                    .get(format!("{scheme}://{}{path}", target.address))
                    .timeout(timeout)
                    .header(
                        "Accept",
                        "text/html, application/json, application/manifest+json",
                    )
                    .header("User-Agent", "Milvago-Discovery/1")
                    .send()
                {
                    if endpoint_scheme.is_none()
                        && scheme == "http"
                        && found.status().as_u16() == 400
                    {
                        continue;
                    }
                    // A response group describes one origin, including transport.
                    // An error on a later path must not switch to another protocol.
                    endpoint_scheme = Some(scheme);
                    response = Some(found);
                    break;
                }
            }
            let Some(response) = response else {
                complete = false;
                continue;
            };
            if response.status().is_redirection()
                || response.content_length().is_some_and(|size| size > 65536)
            {
                complete = false;
                continue;
            }
            #[cfg(target_os = "linux")]
            let connection = response
                .extensions()
                .get::<hyper_util::client::legacy::connect::HttpInfo>()
                .filter(|info| info.remote_addr() == target.address)
                .map(|info| Connection {
                    remote: info.remote_addr(),
                    local: info.local_addr(),
                });
            #[cfg(not(target_os = "linux"))]
            let connection: Option<Connection> = None;
            let status = response.status().as_u16().to_string();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.len() <= 256)
                .and_then(|value| value.split(';').next())
                .map(|value| value.trim().to_ascii_lowercase());
            let mut bytes = vec![];
            if response.take(65537).read_to_end(&mut bytes).is_err() || bytes.len() > 65536 {
                complete = false;
                continue;
            }
            let Ok(body) = String::from_utf8(bytes) else {
                complete = false;
                continue;
            };
            let id = identity("endpoint", &[&snapshot.scope, &target.address.to_string()]);
            if !snapshot.entities.iter().any(|entity| entity.id == id) {
                if snapshot.entities.len() >= MAX_ENTITIES {
                    complete = false;
                    break 'targets;
                }
                snapshot.entities.push(Entity {
                    display: Some(EntityDisplay {
                        address: Some(target.address),
                        ..Default::default()
                    }),
                    id: id.clone(),
                    kind: EntityKind::Endpoint,
                });
                if let Some(origin) = target
                    .origin
                    .as_ref()
                    .filter(|origin| snapshot.entities.iter().any(|entity| entity.id == **origin))
                {
                    if snapshot.relations.len() >= MAX_ENTITIES {
                        complete = false;
                        break 'targets;
                    }
                    snapshot.relations.push(Relation {
                        from: origin.clone(),
                        to: id.clone(),
                        kind: if target.published {
                            RelationKind::PublishedEndpoint
                        } else {
                            RelationKind::OwnsEndpoint
                        },
                        source: if target.published {
                            "container-api-publication"
                        } else {
                            "socket-map"
                        }
                        .into(),
                    });
                }
            }
            let mut fields = BTreeMap::from([
                (Field::HttpStatus, vec![status]),
                (Field::HttpBody, vec![body]),
                (Field::HttpPath, vec![path.clone()]),
            ]);
            if let Some(content_type) = content_type {
                fields.insert(Field::HttpContentType, vec![content_type]);
            }
            if !field_budget.insert(snapshot, &id, Source::Http, fields) {
                complete = false;
                break 'targets;
            }
            if let Some(connection) = connection {
                connections.push(connection);
            }
        }
    }
    coverage(
        snapshot,
        "http",
        if complete {
            CoverageStatus::Available
        } else {
            CoverageStatus::Partial
        },
        complete,
    );
    (consumed, connections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_endpoint_does_not_hide_a_later_service_or_split_its_response_group() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::{Arc, atomic::AtomicBool},
            time::Duration,
        };
        let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
        let healthy = TcpListener::bind("127.0.0.1:0").unwrap();
        let targets: Vec<_> = [&stalled, &healthy]
            .into_iter()
            .map(|listener| Target {
                address: listener.local_addr().unwrap(),
                origin: None,
                published: false,
            })
            .collect();
        let finished = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            for (listener, responds) in [(stalled, false), (healthy, true)] {
                let finished = finished.clone();
                scope.spawn(move || {
                    listener.set_nonblocking(true).unwrap();
                    let mut pending = vec![];
                    while !finished.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                if responds {
                                    stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
                                    stream.set_write_timeout(Some(Duration::from_millis(500))).unwrap();
                                    let mut request = [0; 4096];
                                    let mut used = 0;
                                    while used < request.len() {
                                        let count = stream.read(&mut request[used..]).unwrap();
                                        if count == 0 { break; }
                                        used += count;
                                        if request[..used].windows(4).any(|v| v == b"\r\n\r\n") { break; }
                                    }
                                    assert!(request[..used].starts_with(b"GET /"));
                                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                                } else {
                                    // Keep the socket open without returning headers or a body.
                                    pending.push(stream);
                                    assert!(pending.len() <= 4);
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            Err(error) => panic!("fixture accept: {error}"),
                        }
                    }
                });
            }
            let stop = AtomicBool::new(false);
            let mut snapshot = empty("endpoint", 1, 100);
            let (consumed, _) = collect_paths_with_connections(
                &mut snapshot,
                &targets,
                &[],
                &["/".into(), "/health".into()],
                &Budget::new(Duration::from_secs(3), &stop),
            );
            // Stop fixture threads before asserting, also on regression failure.
            finished.store(true, Ordering::Release);
            assert_eq!(consumed, 2);
            let id = identity("endpoint", &["endpoint", &targets[1].address.to_string()]);
            assert_eq!(snapshot.entities.len(), 1);
            assert_eq!(snapshot.entities[0].id, id);
            assert_eq!(snapshot.facts.len(), 2);
            let paths: std::collections::BTreeSet<_> = snapshot
                .facts
                .iter()
                .map(|fact| fact.fields[&Field::HttpPath][0].as_str())
                .collect();
            assert_eq!(paths, std::collections::BTreeSet::from(["/", "/health"]));
            assert!(
                snapshot
                    .facts
                    .iter()
                    .all(|fact| fact.entity_id == id && fact.source == Source::Http)
            );
            assert!(snapshot.relations.is_empty());
            assert_eq!(snapshot.coverage[0].status, CoverageStatus::Partial);
            milvago_discovery_engine::validate_snapshot(&snapshot).unwrap();
        });
    }

    #[test]
    fn ipv6_metadata_services_are_denied_even_when_explicitly_allowed() {
        for literal in [
            "[fd00:ec2::254]:80",
            "[fd20:ce::254]:443",
            "[FD00:EC2:0:0:0:0:0:254]:80",
        ] {
            let address: std::net::SocketAddr = literal.parse().unwrap();
            assert!(!super::admitted(address, &[address.ip()]));
        }
    }
}
