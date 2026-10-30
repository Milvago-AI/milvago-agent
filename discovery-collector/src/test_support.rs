use crate::*;

// Fill the relationship budget with a valid graph whose entity/fact budgets
// remain small. This exercises independent limits, not duplicate invalid edges.
pub(crate) fn fill_relationships(snapshot: &mut Snapshot) {
    for (kind, prefix, count) in [
        (EntityKind::Host, "qa-host", 129),
        (EntityKind::Endpoint, "qa-endpoint", 128),
    ] {
        for n in 0..count {
            snapshot.entities.push(Entity {
                id: format!("{prefix}/{n}"),
                kind,
                display: None,
            });
        }
    }
    'sources: for from in 0..129 {
        for to in 0..128 {
            if snapshot.relations.len() == MAX_ENTITIES {
                break 'sources;
            }
            snapshot.relations.push(Relation {
                from: format!("qa-host/{from}"),
                to: format!("qa-endpoint/{to}"),
                kind: RelationKind::OwnsEndpoint,
                source: "fixture".into(),
            });
        }
    }
    assert_eq!(snapshot.relations.len(), MAX_ENTITIES);
    validate_snapshot(snapshot).unwrap();
}
