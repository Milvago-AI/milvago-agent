//! Direct containerd metadata API; no inspect/exec command or external CLI.
use crate::*;

#[cfg(unix)]
mod native {
    use super::*;
    use prost::Message;
    use std::{
        future::{Future, poll_fn},
        path::{Path, PathBuf},
        task::Poll,
    };
    use tonic::{
        client::Grpc,
        transport::{Channel, Endpoint},
    };

    #[derive(Clone, PartialEq, Message)]
    struct Empty {}
    #[derive(Clone, PartialEq, Message)]
    struct Namespace {
        #[prost(string, tag = "1")]
        name: String,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Namespaces {
        #[prost(message, repeated, tag = "1")]
        namespaces: Vec<Namespace>,
    }
    // Map values, OCI specs, mounts, extensions and runtime options are skipped
    // by the protobuf decoder. Only label keys are materialized.
    #[derive(Clone, PartialEq, Message)]
    struct LabelKey {
        #[prost(string, tag = "1")]
        key: String,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Container {
        #[prost(string, tag = "1")]
        id: String,
        #[prost(message, repeated, tag = "2")]
        labels: Vec<LabelKey>,
        #[prost(string, tag = "3")]
        image: String,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Containers {
        #[prost(message, repeated, tag = "1")]
        containers: Vec<Container>,
    }
    // Minimal projections of containerd's public tasks/v1 protocol. Stdio,
    // arbitrary ProcessInfo.Any data and runtime specifications are skipped.
    #[derive(Clone, PartialEq, Message)]
    struct Task {
        #[prost(string, tag = "1")]
        container_id: String,
        #[prost(string, tag = "2")]
        id: String,
        #[prost(uint32, tag = "3")]
        pid: u32,
        #[prost(int32, tag = "4")]
        status: i32,
    }
    fn normalize_task_identity(task: &mut Task) -> Result<(), &'static str> {
        // Tasks/List returns the root task in Process.id; containerd's service
        // leaves container_id empty. Accept the legacy explicit field too, but
        // never choose between conflicting identities or infer an exec parent.
        if task.container_id.is_empty() {
            task.container_id = std::mem::take(&mut task.id);
        } else if !task.id.is_empty() && task.id != task.container_id {
            return Err("invalid_task_metadata");
        }
        if !name(&task.container_id) {
            return Err("invalid_task_metadata");
        }
        Ok(())
    }
    #[derive(Clone, PartialEq, Message)]
    struct Tasks {
        #[prost(message, repeated, tag = "1")]
        tasks: Vec<Task>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct PidsRequest {
        #[prost(string, tag = "1")]
        container_id: String,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Pid {
        #[prost(uint32, tag = "1")]
        pid: u32,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Pids {
        #[prost(message, repeated, tag = "1")]
        processes: Vec<Pid>,
    }

    fn name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    }
    async fn cancellable<T>(
        future: impl Future<Output = T>,
        budget: &Budget<'_>,
    ) -> Result<T, &'static str> {
        budget.check()?;
        let mut future = Box::pin(future);
        let mut tick = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(50)));
        let deadline = tokio::time::Instant::now() + budget.remaining()?;
        poll_fn(move |context| {
            if let Poll::Ready(value) = future.as_mut().poll(context) {
                return Poll::Ready(Ok(value));
            }
            if tick.as_mut().poll(context).is_ready() {
                if let Err(error) = budget.check() {
                    return Poll::Ready(Err(error));
                }
                if tokio::time::Instant::now() >= deadline {
                    return Poll::Ready(Err("timeout"));
                }
                tick.as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(50));
            }
            Poll::Pending
        })
        .await
    }
    struct Client {
        grpc: Grpc<Channel>,
        runtime: tokio::runtime::Runtime,
        #[cfg(target_os = "linux")]
        peer: std::sync::Arc<std::sync::Mutex<Option<crate::containerd_process::Peer>>>,
    }
    impl Client {
        fn connect(path: &Path, budget: &Budget<'_>) -> Result<Self, &'static str> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|_| "runtime_unavailable")?;
            let path = path.to_path_buf();
            #[cfg(target_os = "linux")]
            let peer = std::sync::Arc::new(std::sync::Mutex::new(None));
            #[cfg(target_os = "linux")]
            let connector_peer = peer.clone();
            let endpoint = Endpoint::from_static("http://localhost")
                .connect_timeout(budget.remaining()?)
                .timeout(budget.remaining()?)
                .concurrency_limit(1)
                .buffer_size(1)
                .initial_stream_window_size(65535)
                .initial_connection_window_size(65535)
                .http2_adaptive_window(false)
                .http2_max_header_list_size(16384)
                .http2_header_table_size(4096)
                .max_frame_size(16384);
            let channel = runtime
                .block_on(cancellable(
                    endpoint.connect_with_connector(tower::service_fn(move |_| {
                        let path = path.clone();
                        #[cfg(target_os = "linux")]
                        let peer = connector_peer.clone();
                        async move {
                            let stream = tokio::net::UnixStream::connect(path).await?;
                            #[cfg(target_os = "linux")]
                            {
                                let credentials = stream.peer_cred()?;
                                let verified = credentials
                                    .pid()
                                    .and_then(|pid| u32::try_from(pid).ok())
                                    .and_then(|pid| {
                                        crate::containerd_process::Peer::read(
                                            pid,
                                            credentials.uid(),
                                        )
                                    });
                                *peer
                                    .lock()
                                    .map_err(|_| std::io::Error::other("peer_guard"))? = verified;
                            }
                            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                        }
                    })),
                    budget,
                ))?
                .map_err(|_| "engine_transport")?;
            Ok(Self {
                grpc: Grpc::new(channel)
                    .max_decoding_message_size(512 * 1024)
                    .max_encoding_message_size(1024),
                runtime,
                #[cfg(target_os = "linux")]
                peer,
            })
        }
        fn list<T: Message + Default + Send + Sync + 'static>(
            &mut self,
            path: &'static str,
            namespace: Option<&str>,
            budget: &Budget<'_>,
        ) -> Result<T, &'static str> {
            self.request(path, namespace, Empty {}, budget)
        }
        fn request<Q, T>(
            &mut self,
            path: &'static str,
            namespace: Option<&str>,
            message: Q,
            budget: &Budget<'_>,
        ) -> Result<T, &'static str>
        where
            Q: Message + Default + Send + Sync + 'static,
            T: Message + Default + Send + Sync + 'static,
        {
            budget.check()?;
            let mut request = tonic::Request::new(message);
            request.set_timeout(budget.remaining()?);
            if let Some(namespace) = namespace {
                if !name(namespace) {
                    return Err("invalid_namespace");
                }
                request.metadata_mut().insert(
                    "containerd-namespace",
                    namespace.parse().map_err(|_| "invalid_namespace")?,
                );
            }
            let grpc = &mut self.grpc;
            self.runtime.block_on(cancellable(
                async {
                    grpc.ready().await.map_err(|_| "engine_transport")?;
                    grpc.unary(
                        request,
                        tonic::codegen::http::uri::PathAndQuery::from_static(path),
                        tonic_prost::ProstCodec::<Q, T>::default(),
                    )
                    .await
                    .map(|reply| reply.into_inner())
                    .map_err(|status| match status.code() {
                        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
                            "access_denied"
                        }
                        tonic::Code::ResourceExhausted => "response_limit",
                        _ => "engine_transport",
                    })
                },
                budget,
            ))?
        }
        #[cfg(target_os = "linux")]
        fn peer(&self) -> Result<crate::containerd_process::Peer, &'static str> {
            self.peer
                .lock()
                .map_err(|_| "peer_guard")?
                .clone()
                .filter(|peer| peer.current())
                .ok_or("unverified_engine_peer")
        }
    }
    pub(super) fn sockets() -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from("/run/containerd/containerd.sock"),
            PathBuf::from("/run/k3s/containerd/containerd.sock"),
            PathBuf::from("/run/rke2/containerd/containerd.sock"),
        ];
        if let Ok(users) = std::fs::read_dir("/run/user") {
            for user in users.flatten().take(64) {
                if user
                    .file_name()
                    .to_str()
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                {
                    paths.push(user.path().join("containerd-rootless/containerd.sock"));
                }
            }
        }
        paths
            .into_iter()
            .filter(|path| path.exists())
            .take(16)
            .collect()
    }
    fn project(
        snapshot: &mut Snapshot,
        socket: &str,
        namespace: &str,
        rows: Containers,
        budget: &Budget<'_>,
    ) -> Result<(), &'static str> {
        if !name(namespace) || rows.containers.len() > 1000 {
            return Err("container_limit");
        }
        let runtime = identity("runtime", &["containerd", socket, namespace]);
        let mut entities = vec![];
        let mut facts = vec![];
        let mut seen = std::collections::BTreeSet::new();
        for row in rows.containers {
            budget.check()?;
            if !name(&row.id) || !seen.insert(row.id.clone()) || row.labels.len() > 128 {
                return Err("invalid_container_metadata");
            }
            let entity = identity("container", &[&runtime, &row.id]);
            let mut fields = BTreeMap::from([(Field::ContainerName, vec![row.id])]);
            if let Some(repository) = crate::containers::repository(&row.image) {
                fields.insert(Field::ImageRepository, vec![repository]);
            }
            let keys: Vec<_> = row
                .labels
                .into_iter()
                .map(|label| label.key)
                .filter(|key| {
                    !key.is_empty() && key.len() <= 160 && !key.chars().any(char::is_control)
                })
                .take(64)
                .collect();
            if !keys.is_empty() {
                fields.insert(Field::Label, keys);
            }
            entities.push(entity);
            facts.push(fields);
        }
        if snapshot.entities.len() + entities.len() + 1 > MAX_ENTITIES
            || snapshot.relations.len() + entities.len() + 1 > MAX_ENTITIES
            || snapshot.facts.len() + facts.len() > MAX_FACTS
        {
            return Err("container_limit");
        }
        if snapshot.entities.iter().any(|entity| entity.id == runtime) {
            return Err("duplicate_runtime");
        }
        snapshot.entities.push(Entity {
            display: Some(EntityDisplay {
                name: Some("containerd".into()),
                ..Default::default()
            }),
            id: runtime.clone(),
            kind: EntityKind::Runtime,
        });
        if let Some(host) = snapshot
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Host)
        {
            snapshot.relations.push(Relation {
                from: host.id.clone(),
                to: runtime.clone(),
                kind: RelationKind::Contains,
                source: "containerd-api".into(),
            });
        }
        let mut field_budget = FieldBudget::new(snapshot);
        for (entity, fields) in entities.into_iter().zip(facts) {
            snapshot.entities.push(Entity {
                display: Some(EntityDisplay {
                    name: fields
                        .get(&Field::ContainerName)
                        .and_then(|v| v.first())
                        .cloned(),
                    image: fields
                        .get(&Field::ImageRepository)
                        .and_then(|v| v.first())
                        .cloned(),
                    ..Default::default()
                }),
                id: entity.clone(),
                kind: EntityKind::Container,
            });
            snapshot.relations.push(Relation {
                from: runtime.clone(),
                to: entity.clone(),
                kind: RelationKind::Contains,
                source: "containerd-api".into(),
            });
            if !field_budget.insert(snapshot, &entity, Source::ContainerMetadata, fields) {
                return Err("fact_limit");
            }
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn processes(
        snapshot: &mut Snapshot,
        client: &mut Client,
        socket: &str,
        namespace: &str,
        budget: &Budget<'_>,
        remaining: &mut usize,
    ) -> Result<(Vec<host::Listener>, bool), &'static str> {
        let peer = client.peer()?;
        let mut rows: Tasks = client.list(
            "/containerd.services.tasks.v1.Tasks/List",
            Some(namespace),
            budget,
        )?;
        if client.peer()? != peer || rows.tasks.len() > 1000 {
            return Err("unverified_tasks");
        }
        let runtime = identity("runtime", &["containerd", socket, namespace]);
        let mut seen = std::collections::BTreeSet::new();
        for task in &mut rows.tasks {
            normalize_task_identity(task)?;
            let container = identity("container", &[&runtime, &task.container_id]);
            if !name(&task.container_id)
                || !seen.insert(task.container_id.as_str())
                || !snapshot
                    .entities
                    .iter()
                    .any(|e| e.id == container && e.kind == EntityKind::Container)
            {
                return Err("invalid_task_metadata");
            }
        }
        rows.tasks
            .sort_by(|a, b| a.container_id.cmp(&b.container_id));
        if !rows.tasks.is_empty() {
            let offset = (snapshot.sequence as usize).wrapping_mul(16) % rows.tasks.len();
            rows.tasks.rotate_left(offset);
        }
        let mut complete = rows.tasks.len() <= 16;
        let mut listeners = vec![];
        for task in rows.tasks.into_iter().take(16) {
            budget.check()?;
            // Created, stopped, paused or unknown tasks cannot establish running software.
            if task.status != 2 {
                if task.status == 0 {
                    complete = false;
                }
                continue;
            }
            if task.pid == 0 || *remaining == 0 {
                complete = false;
                continue;
            }
            let pids: Pids = match client.request(
                "/containerd.services.tasks.v1.Tasks/ListPids",
                Some(namespace),
                PidsRequest {
                    container_id: task.container_id.clone(),
                },
                budget,
            ) {
                Ok(value) => value,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if client.peer()? != peer || pids.processes.len() > 1024 {
                return Err("unverified_tasks");
            }
            let mut pids = pids
                .processes
                .into_iter()
                .map(|p| p.pid)
                .collect::<Vec<_>>();
            if pids.iter().any(|p| *p == 0) || !pids.contains(&task.pid) {
                complete = false;
                continue;
            }
            pids.sort_unstable();
            pids.dedup();
            let length = pids.len();
            if length > 0 {
                pids.rotate_left((snapshot.sequence as usize).wrapping_mul(64) % length);
            }
            let container = identity("container", &[&runtime, &task.container_id]);
            for pid in pids {
                if *remaining == 0 {
                    complete = false;
                    break;
                }
                *remaining -= 1;
                match crate::containerd_process::project(
                    snapshot,
                    &peer,
                    &container,
                    &task.container_id,
                    pid,
                    budget,
                ) {
                    Ok(projection) => {
                        listeners.extend(projection.listeners);
                        complete &= projection.complete;
                    }
                    Err(_) => complete = false,
                }
            }
        }
        Ok((listeners, complete))
    }
    pub(super) fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) -> Vec<host::Listener> {
        let mut sockets = sockets();
        sockets.sort();
        if !sockets.is_empty() {
            let offset = snapshot.sequence as usize % sockets.len();
            sockets.rotate_left(offset);
        }
        let mut complete = !sockets.is_empty();
        let mut process_complete = complete;
        let mut listeners = vec![];
        #[cfg(target_os = "linux")]
        let mut remaining = 64;
        for socket in sockets {
            if budget.check().is_err() {
                complete = false;
                break;
            }
            let mut client = match Client::connect(&socket, budget) {
                Ok(client) => client,
                Err(_) => {
                    complete = false;
                    process_complete = false;
                    continue;
                }
            };
            let mut namespaces: Namespaces = match client.list(
                "/containerd.services.namespaces.v1.Namespaces/List",
                None,
                budget,
            ) {
                Ok(rows) => rows,
                Err(_) => {
                    complete = false;
                    process_complete = false;
                    continue;
                }
            };
            if namespaces.namespaces.len() > 64 {
                complete = false;
                process_complete = false;
                continue;
            }
            namespaces.namespaces.sort_by(|a, b| a.name.cmp(&b.name));
            if !namespaces.namespaces.is_empty() {
                let offset = snapshot.sequence as usize % namespaces.namespaces.len();
                namespaces.namespaces.rotate_left(offset);
            }
            for namespace in namespaces.namespaces {
                if !name(&namespace.name) || budget.check().is_err() {
                    complete = false;
                    break;
                }
                let rows = client
                    .list(
                        "/containerd.services.containers.v1.Containers/List",
                        Some(&namespace.name),
                        budget,
                    )
                    .and_then(|rows| {
                        project(
                            snapshot,
                            &socket.to_string_lossy(),
                            &namespace.name,
                            rows,
                            budget,
                        )
                    });
                if rows.is_err() {
                    complete = false;
                    process_complete = false;
                    continue;
                }
                #[cfg(target_os = "linux")]
                match processes(
                    snapshot,
                    &mut client,
                    &socket.to_string_lossy(),
                    &namespace.name,
                    budget,
                    &mut remaining,
                ) {
                    Ok((ports, exhaustive)) => {
                        listeners.extend(ports);
                        process_complete &= exhaustive;
                    }
                    Err(_) => process_complete = false,
                }
            }
        }
        coverage(
            snapshot,
            "containerd-metadata",
            if complete {
                CoverageStatus::Available
            } else {
                CoverageStatus::Partial
            },
            complete,
        );
        coverage(
            snapshot,
            "containerd-processes",
            if cfg!(target_os = "linux") {
                if process_complete && complete {
                    CoverageStatus::Available
                } else {
                    CoverageStatus::Partial
                }
            } else {
                CoverageStatus::Unavailable
            },
            cfg!(target_os = "linux") && process_complete && complete,
        );
        listeners
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{sync::atomic::AtomicBool, time::Duration};
        #[test]
        fn task_list_uses_the_real_id_wire_field_and_rejects_conflicts() {
            // Independent protobuf bytes: field2=id, field3=pid, field4=status.
            let mut task = Task::decode(b"\x12\x07fixture\x18\x07\x20\x02".as_slice()).unwrap();
            assert!(task.container_id.is_empty());
            normalize_task_identity(&mut task).unwrap();
            assert_eq!(task.container_id, "fixture");
            assert_eq!((task.pid, task.status), (7, 2));
            for (container_id, id, accepted) in [
                ("fixture", "", true),
                ("fixture", "fixture", true),
                ("fixture", "other", false),
                ("", "", false),
                ("", "../fixture", false),
                ("", "fixture\n", false),
            ] {
                let mut task = Task { container_id: container_id.into(), id: id.into(), ..Default::default() };
                assert_eq!(normalize_task_identity(&mut task).is_ok(), accepted);
            }
        }
        #[cfg(target_os = "linux")]
        #[test]
        fn tasks_rpc_ignores_stopped_tasks_and_rejects_uncorroborated_host_pids() {
            use std::{os::unix::net::UnixListener, thread};
            let directory = std::env::temp_dir().join(format!(
                "milvago-tasks-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&directory).unwrap();
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0.join("api.sock"));
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            let _cleanup = Cleanup(directory.clone());
            let socket = directory.join("api.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let pid = std::process::id();
            let server = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                    tokio::time::timeout(Duration::from_secs(10), async {
                        let (stream, _) = listener.accept().await.unwrap();
                        let mut connection = h2::server::handshake(stream).await.unwrap();
                        let mut index = 0;
                        let mut handlers = vec![];
                        while let Some(request) = connection.accept().await {
                            let (request, mut response) = request.unwrap();
                            let mode = index;
                            index += 1;
                            handlers.push(tokio::spawn(async move {
                                assert_eq!(
                                    request.headers().get("containerd-namespace").unwrap(),
                                    "default"
                                );
                                let expected = if mode < 2 {
                                    "/containerd.services.tasks.v1.Tasks/List"
                                } else {
                                    "/containerd.services.tasks.v1.Tasks/ListPids"
                                };
                                assert_eq!(request.uri().path(), expected);
                                let mut body = request.into_body();
                                let mut data = vec![];
                                while let Some(bytes) = body.data().await {
                                    let bytes = bytes.unwrap();
                                    body.flow_control().release_capacity(bytes.len()).unwrap();
                                    data.extend_from_slice(&bytes);
                                }
                                let payload = if mode < 2 {
                                    assert_eq!(data, [0, 0, 0, 0, 0]);
                                    Tasks {
                                        tasks: vec![Task {
                                            container_id: if mode == 0 { "fixture".into() } else { String::new() },
                                            id: if mode == 0 { String::new() } else { "fixture".into() },
                                            pid,
                                            status: if mode == 0 { 3 } else { 2 },
                                        }],
                                    }
                                    .encode_to_vec()
                                } else {
                                    assert_eq!(
                                        PidsRequest::decode(&data[5..]).unwrap().container_id,
                                        "fixture"
                                    );
                                    Pids {
                                        processes: vec![Pid { pid }],
                                    }
                                    .encode_to_vec()
                                };
                                let mut frame = vec![0];
                                frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                frame.extend(payload);
                                let headers = ::http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                let mut stream = response.send_response(headers, false).unwrap();
                                stream.send_data(bytes::Bytes::from(frame), false).unwrap();
                                let mut trailers = ::http::HeaderMap::new();
                                trailers
                                    .insert("grpc-status", ::http::HeaderValue::from_static("0"));
                                stream.send_trailers(trailers).unwrap();
                            }));
                        }
                        for handler in handlers {
                            handler.await.unwrap();
                        }
                        assert_eq!(index, 3);
                    })
                    .await
                    .unwrap();
                });
            });
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(5), &stop);
            let mut client = Client::connect(&socket, &budget).unwrap();
            assert!(client.peer().is_ok());
            let mut snapshot = empty("endpoint", 1, 100);
            project(
                &mut snapshot,
                "/fixture/socket",
                "default",
                Containers {
                    containers: vec![Container {
                        id: "fixture".into(),
                        labels: vec![],
                        image: "ollama/ollama:fixture".into(),
                    }],
                },
                &budget,
            )
            .unwrap();
            let mut remaining = 64;
            let (ports, complete) = processes(
                &mut snapshot,
                &mut client,
                "/fixture/socket",
                "default",
                &budget,
                &mut remaining,
            )
            .unwrap();
            assert!(ports.is_empty() && complete);
            assert_eq!(remaining, 64);
            let (ports, complete) = processes(
                &mut snapshot,
                &mut client,
                "/fixture/socket",
                "default",
                &budget,
                &mut remaining,
            )
            .unwrap();
            assert!(ports.is_empty() && !complete);
            assert_eq!(remaining, 63);
            assert!(
                snapshot
                    .facts
                    .iter()
                    .all(|f| f.source == Source::ContainerMetadata)
            );
            assert!(
                !snapshot
                    .entities
                    .iter()
                    .any(|e| e.kind == EntityKind::Process)
            );
            drop(client);
            server.join().unwrap();
        }
        #[test]
        fn protobuf_projects_image_and_label_keys_without_specs_or_label_values() {
            // Container image and a map entry; value tag 2 and OCI spec tag 5
            // are unknown to the projection and never become allocated strings.
            let mut bytes = Container {
                id: "fixture-container".into(),
                image: "ollama/ollama:fixture".into(),
                labels: vec![],
            }
            .encode_to_vec();
            let secret = b"PRIVATE";
            let mut map = vec![10, 3, b'k', b'e', b'y', 18, secret.len() as u8];
            map.extend_from_slice(secret);
            bytes.extend_from_slice(&[18, map.len() as u8]);
            bytes.extend(map);
            bytes.extend_from_slice(&[42, secret.len() as u8]);
            bytes.extend_from_slice(secret);
            let row = Container::decode(bytes.as_slice()).unwrap();
            assert_eq!(row.labels[0].key, "key");
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(1), &stop);
            let mut snapshot = empty("endpoint", 1, 100);
            project(
                &mut snapshot,
                "/fixture/socket",
                "default",
                Containers {
                    containers: vec![row],
                },
                &budget,
            )
            .unwrap();
            assert!(
                !serde_json::to_string(&snapshot)
                    .unwrap()
                    .contains("PRIVATE")
            );
            assert_eq!(snapshot.facts[0].source, Source::ContainerMetadata);
            let factory: Catalog = serde_json::from_slice(include_bytes!(
                "../../discovery-engine/catalog/factory.json"
            ))
            .unwrap();
            let result = Engine::compile(&factory)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap();
            assert_eq!(result.identifications[0].state, State::Indication);
            crate::test_support::fill_relationships(&mut snapshot);
            let before = serde_json::to_vec(&snapshot).unwrap();
            assert_eq!(
                project(
                    &mut snapshot,
                    "/fixture/socket",
                    "other",
                    Containers { containers: vec![Container { id: "other".into(), image: "ollama/ollama:fixture".into(), labels: vec![] }] },
                    &budget,
                ),
                Err("container_limit")
            );
            assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
            assert_eq!(Engine::compile(&factory).unwrap().evaluate(&snapshot).unwrap().identifications[0].state, State::Indication);
        }
        #[test]
        fn namespace_and_container_ids_are_bounded_and_no_projection_is_half_applied() {
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(1), &stop);
            let mut snapshot = empty("endpoint", 1, 100);
            for namespace in ["", "../other", "x\r\nheader", "data:image/png"] {
                assert!(!name(namespace));
            }
            let rows = Containers {
                containers: vec![
                    Container {
                        id: "valid".into(),
                        image: "ollama/ollama".into(),
                        labels: vec![],
                    },
                    Container {
                        id: "invalid/id".into(),
                        image: String::new(),
                        labels: vec![],
                    },
                ],
            };
            assert!(project(&mut snapshot, "/fixture/socket", "default", rows, &budget).is_err());
            assert!(snapshot.entities.is_empty());
            assert!(snapshot.facts.is_empty());
        }

        #[test]
        fn real_unix_grpc_transport_checks_trailers_size_timeout_and_closes_its_runtime() {
            use std::{os::unix::net::UnixListener, sync::mpsc, thread};
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "milvago-discovery-containerd-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            struct Cleanup(PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0.join("api.sock"));
                    let _ = std::fs::remove_dir(&self.0);
                }
            }
            let _cleanup = Cleanup(directory.clone());
            let socket = directory.join("api.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let (done_tx, done_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                    tokio::time::timeout(Duration::from_secs(15), async {
                        for mode in 0..4 {
                            let (stream, _) = listener.accept().await.unwrap();
                            let mut connection = h2::server::handshake(stream).await.unwrap();
                            let mut handlers = vec![];
                            while let Some(request) = connection.accept().await {
                                let (request, mut response) = match request {
                                    Ok(request) => request,
                                    Err(_) => break,
                                };
                                handlers.push(tokio::spawn(async move {
                                    assert_eq!(request.method(), ::http::Method::POST);
                                    assert_eq!(
                                        request.uri().path(),
                                        "/containerd.services.namespaces.v1.Namespaces/List"
                                    );
                                    let mut incoming = request.into_body();
                                    while let Some(bytes) = incoming.data().await {
                                        let bytes = bytes.unwrap();
                                        incoming
                                            .flow_control()
                                            .release_capacity(bytes.len())
                                            .unwrap();
                                    }
                                    // No mutating RPC can be selected through catalogue data.
                                    if mode == 3 {
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                        return;
                                    }
                                    let body = Namespaces {
                                        namespaces: vec![Namespace {
                                            name: "default".into(),
                                        }],
                                    }
                                    .encode_to_vec();
                                    let mut frame = vec![0];
                                    frame.extend_from_slice(
                                        &(if mode == 2 {
                                            512 * 1024 + 1
                                        } else {
                                            body.len()
                                        } as u32)
                                            .to_be_bytes(),
                                    );
                                    if mode != 2 {
                                        frame.extend(body);
                                    }
                                    let headers = ::http::Response::builder()
                                        .status(200)
                                        .header("content-type", "application/grpc")
                                        .body(())
                                        .unwrap();
                                    let mut stream =
                                        response.send_response(headers, false).unwrap();
                                    stream.send_data(bytes::Bytes::from(frame), false).unwrap();
                                    let mut trailers = ::http::HeaderMap::new();
                                    trailers.insert(
                                        "grpc-status",
                                        if mode == 1 {
                                            ::http::HeaderValue::from_static("7")
                                        } else {
                                            ::http::HeaderValue::from_static("0")
                                        },
                                    );
                                    stream.send_trailers(trailers).unwrap();
                                }));
                            }
                            for handler in handlers {
                                handler.await.unwrap();
                            }
                        }
                    })
                    .await
                    .expect("bounded gRPC fixture did not finish");
                });
                done_tx.send(()).unwrap();
            });
            let stop = AtomicBool::new(false);
            for mode in 0..4 {
                let budget = Budget::new(Duration::from_secs(4), &stop);
                let mut client = Client::connect(&socket, &budget).unwrap();
                let start = std::time::Instant::now();
                let response = client.list::<Namespaces>(
                    "/containerd.services.namespaces.v1.Namespaces/List",
                    None,
                    &budget,
                );
                match mode {
                    0 => assert_eq!(response.unwrap().namespaces[0].name, "default"),
                    1 => assert_eq!(response.unwrap_err(), "access_denied"),
                    2 => assert!(response.is_err()),
                    _ => {
                        assert!(response.is_err());
                        assert!(start.elapsed() < Duration::from_secs(3));
                    }
                }
                drop(client);
            }
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("gRPC runtime or connection remained alive after client drop");
            server.join().unwrap();
        }
    }
}
pub fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) -> Vec<host::Listener> {
    #[cfg(unix)]
    {
        native::collect(snapshot, budget)
    }
    #[cfg(not(unix))]
    {
        let _ = budget;
        coverage(snapshot, "containerd", CoverageStatus::Unavailable, false);
        vec![]
    }
}
