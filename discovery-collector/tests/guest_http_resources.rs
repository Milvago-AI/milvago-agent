use milvago_discovery_engine::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

struct CountingAllocator;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, old, size) };
        if !result.is_null() {
            LIVE.fetch_add(size as isize - old.size() as isize, Ordering::Relaxed);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

use milvago_discovery_collector::{empty, guest::Access, guest_http};

#[test]
fn repeated_guest_http_success_and_rejection_release_their_live_allocations() {
    let paths: Vec<String> = (0..8)
        .map(|index| {
            if index == 0 {
                "/".into()
            } else {
                format!("/p{index}")
            }
        })
        .collect();
    let body = format!("Ollama is running{}", "x".repeat(1007));
    assert_eq!(body.len(), 1024);
    let mut rows = vec![];
    for port in 32100..32116 {
        for path in &paths {
            rows.push(serde_json::json!({"port":port,"path":path,"status":200,"content_type":"text/plain","body":if path == "/" {"Ollama is running"} else {body.as_str()}}));
        }
    }
    let good = serde_json::to_vec(&serde_json::json!({"complete":false,"responses":rows})).unwrap();
    rows[127]["path"] = "/not-authorized".into();
    let bad = serde_json::to_vec(&serde_json::json!({"complete":false,"responses":rows})).unwrap();
    drop(rows);
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let round = |input: &[u8], accepted: bool| {
        let mut snapshot = empty("endpoint", 1, 100);
        snapshot.entities.push(Entity {
            id: "vm/fixture".into(),
            kind: EntityKind::Vm,
            display: None,
        });
        let input: guest_http::Responses = serde_json::from_slice(input).unwrap();
        let result = guest_http::project(
            &mut snapshot,
            "vm/fixture",
            "boot/fixture",
            input,
            &paths,
            Access {
                read: true,
                execute: true,
            },
        );
        assert_eq!(result.is_ok(), accepted);
        validate_snapshot(&snapshot).unwrap();
        if accepted {
            assert_eq!(snapshot.facts.len(), 128);
            assert_eq!(snapshot.entities.len(), 17);
            let result = engine.evaluate(&snapshot).unwrap();
            assert_eq!(result.identifications.len(), 16);
            assert!(result.communications.is_empty());
            for page in report::pages(&snapshot, &result, catalog.revision, 1).unwrap() {
                report::validate(&page, &catalog).unwrap();
                let wire = serde_json::to_string(&page).unwrap();
                assert!(!wire.contains("Ollama is running"));
            }
        } else {
            assert!(snapshot.facts.is_empty());
            assert!(snapshot.relations.is_empty());
            assert_eq!(snapshot.entities.len(), 1);
        }
    };
    for _ in 0..4 {
        round(&good, true);
        round(&bad, false);
    }
    let baseline = LIVE.load(Ordering::SeqCst);
    for _ in 0..500 {
        round(&good, true);
        round(&bad, false);
    }
    assert_eq!(
        LIVE.load(Ordering::SeqCst),
        baseline,
        "guest HTTP allocations retained after success/rejection cycles"
    );
}
