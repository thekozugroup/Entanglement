//! Operator policy, revocation and key-based grants (spec §4.5, §4.6): every
//! decision is audited and counted with its reason.

use entangle_broker::{
    AuditEvent, Broker, BrokerError, BrokerPolicy, CapabilityPattern, GrantState,
};
use entangle_manifest::{schema::Manifest, validate::validate, ValidatedManifest};
use entangle_observability::catalog::names;
use entangle_observability::Registry;
use entangle_types::capability::{CapabilityKind, StorageMode, StorageScope};
use entangle_types::plugin_id::PluginId;

const PUB: &str = "aabbccddeeff00112233445566778899";

fn manifest(name: &str, caps: &str) -> ValidatedManifest {
    let text = format!(
        r#"
[plugin]
id = "{PUB}/{name}@0.1.0"
version = "0.1.0"
tier = 3
runtime = "wasm"

[capabilities]
{caps}
"#
    );
    let raw: Manifest = toml::from_str(&text).expect("toml");
    validate(raw).expect("valid manifest")
}

const CAPS: &str = r#"
"compute.cpu" = {}
"net.lan" = {}
"net.wan" = { hosts = ["api.example.com:443"] }
"storage.local" = { mode = "ro" }
"#;

fn policy(deny: &[&str]) -> BrokerPolicy {
    BrokerPolicy {
        denied_capabilities: deny
            .iter()
            .map(|p| p.parse::<CapabilityPattern>().unwrap())
            .collect(),
        ..Default::default()
    }
}

fn denial_count(reg: &Registry, family: &str, reason: &str) -> Option<f64> {
    reg.value(
        names::CAPABILITY_DENIALS,
        &[("capability", family), ("reason", reason)],
    )
}

fn denied_reasons(broker: &Broker, plugin: &PluginId) -> Vec<(String, String)> {
    broker
        .audit_log()
        .snapshot()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::CapabilityDenied {
                plugin: p,
                capability,
                reason,
                ..
            } if &p == plugin => Some((capability.into_owned(), reason.into_owned())),
            _ => None,
        })
        .collect()
}

/// §4.5: a plugin declaring a capability the operator denies still loads
/// (registers); that capability alone is refused, audited and counted.
#[test]
fn grant_declared_grants_all_but_operator_denied_capabilities() {
    let reg = Registry::new();
    let broker = Broker::new(policy(&["net.wan"])).with_metrics(reg.clone());
    let m = manifest("resolve", CAPS);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();

    let res = broker.grant_declared(&id).unwrap();
    let granted: Vec<String> = res
        .granted
        .iter()
        .map(|g| g.kind.key().into_owned())
        .collect();
    assert_eq!(granted, ["compute.cpu", "net.lan", "storage.local"]);
    assert_eq!(res.denied.len(), 1);
    assert_eq!(res.denied[0].0.key(), "net.wan");
    assert!(
        res.denied[0].1.contains("ENTANGLE-E0124"),
        "{}",
        res.denied[0].1
    );

    let reasons = denied_reasons(&broker, &id);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(reasons[0].0.starts_with("net.wan"), "{reasons:?}");
    assert!(reasons[0].1.contains("operator policy"), "{reasons:?}");
    assert_eq!(denial_count(&reg, "net.wan", "operator_policy"), Some(1.0));
    assert_eq!(
        reg.value(names::CAPABILITY_GRANTS, &[("capability", "storage.local")]),
        Some(1.0)
    );

    // The report shows the standing grants and the denial.
    let report = broker.capability_report(&id).unwrap();
    for status in &report {
        match status.capability.key().as_ref() {
            "net.wan" => assert!(
                matches!(&status.state, GrantState::Denied { reason } if reason.contains("net.wan")),
                "{status:?}"
            ),
            _ => assert!(
                matches!(&status.state, GrantState::Granted { grant_ids } if grant_ids.len() == 1),
                "{status:?}"
            ),
        }
    }
}

/// Family patterns deny every member; a direct grant of a denied capability
/// fails with ENTANGLE-E0124 too.
#[test]
fn family_patterns_deny_every_member() {
    let broker = Broker::new(policy(&["net.*"]));
    let m = manifest("family", CAPS);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();
    let err = broker.grant(&id, &CapabilityKind::NetLan).unwrap_err();
    assert!(
        matches!(&err, BrokerError::CapabilityDeniedByPolicy { pattern, .. } if pattern == "net.*"),
        "{err}"
    );
    let err = broker.grant_by_key(&id, "net.wan").unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityDeniedByPolicy { .. }),
        "{err}"
    );
    broker.grant(&id, &CapabilityKind::ComputeCpu).unwrap();
}

/// `grant_by_key` takes the parameters from the manifest; a key the
/// manifest does not declare is a (counted, audited) `not_declared` denial.
#[test]
fn grant_by_key_uses_declared_parameters() {
    let reg = Registry::new();
    let broker = Broker::new(BrokerPolicy::default()).with_metrics(reg.clone());
    let m = manifest("bykey", CAPS);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();

    let g = broker.grant_by_key(&id, "storage.local").unwrap();
    assert_eq!(
        g.kind,
        CapabilityKind::StorageLocal {
            scope: StorageScope::Plugin,
            mode: StorageMode::Ro
        }
    );
    let g = broker.grant_by_key(&id, "net.wan").unwrap();
    assert_eq!(g.kind.params(), "hosts=api.example.com:443");

    for key in ["compute.gpu", "storage.share.photos", "custom.anything"] {
        let err = broker.grant_by_key(&id, key).unwrap_err();
        assert!(
            matches!(err, BrokerError::CapabilityNotDeclared { .. }),
            "{key}: {err}"
        );
    }
    assert_eq!(denial_count(&reg, "compute.gpu", "not_declared"), Some(1.0));
    assert_eq!(
        denial_count(&reg, "storage.share", "not_declared"),
        Some(1.0)
    );
    assert_eq!(denial_count(&reg, "custom", "not_declared"), Some(1.0));
    // Share names and custom strings never become label values.
    let text = reg.render();
    assert!(
        !text.contains("photos") && !text.contains("anything"),
        "{text}"
    );
    let reasons = denied_reasons(&broker, &id);
    assert!(
        reasons
            .iter()
            .any(|(c, r)| c == "storage.share.photos" && r.contains("not declared")),
        "{reasons:?}"
    );

    // A parameter mismatch is not the declared capability either.
    let err = broker
        .grant(
            &id,
            &CapabilityKind::StorageLocal {
                scope: StorageScope::Plugin,
                mode: StorageMode::Rw,
            },
        )
        .unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityNotDeclared { .. }),
        "{err}"
    );
}

/// §4.6: revocation withdraws every outstanding grant of the capability,
/// is audited, and makes later requests fail as revoked (ENTANGLE-E0125)
/// with the `revoked` metric reason.
#[test]
fn revoke_withdraws_grants_and_refuses_later_requests() {
    let reg = Registry::new();
    let broker = Broker::new(BrokerPolicy::default()).with_metrics(reg.clone());
    let m = manifest("revoke", CAPS);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();

    let standing = broker.grant_declared(&id).unwrap();
    let lan = standing
        .granted
        .iter()
        .find(|g| g.kind == CapabilityKind::NetLan)
        .unwrap()
        .grant_id;
    let fetched = broker.grant_by_key(&id, "net.lan").unwrap().grant_id;
    assert!(broker.is_live(&id, lan) && broker.is_live(&id, fetched));

    let withdrawn = broker.revoke(&id, "net.lan").unwrap();
    assert_eq!(withdrawn, vec![lan.min(fetched), lan.max(fetched)]);
    assert!(!broker.is_live(&id, lan) && !broker.is_live(&id, fetched));
    // Other capabilities are untouched.
    let cpu = standing
        .granted
        .iter()
        .find(|g| g.kind == CapabilityKind::ComputeCpu)
        .unwrap()
        .grant_id;
    assert!(broker.is_live(&id, cpu));

    let revoked_events: Vec<_> = broker
        .audit_log()
        .snapshot()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::CapabilityRevoked {
                capability,
                grant_ids,
                ..
            } => Some((capability.into_owned(), grant_ids)),
            _ => None,
        })
        .collect();
    assert_eq!(
        revoked_events,
        vec![("net.lan".to_owned(), withdrawn.clone())]
    );

    let err = broker.grant_by_key(&id, "net.lan").unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityRevoked { .. }),
        "{err}"
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0125"), "{err}");
    let err = broker.grant(&id, &CapabilityKind::NetLan).unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityRevoked { .. }),
        "{err}"
    );
    assert_eq!(denial_count(&reg, "net.lan", "revoked"), Some(2.0));

    // Idempotent: nothing left to withdraw, no second audit event.
    assert!(broker.revoke(&id, "net.lan").unwrap().is_empty());
    let n = broker
        .audit_log()
        .snapshot()
        .iter()
        .filter(|e| matches!(e, AuditEvent::CapabilityRevoked { .. }))
        .count();
    assert_eq!(n, 1);

    // Revoking something the plugin never declared is an error, not a no-op.
    let err = broker.revoke(&id, "compute.gpu").unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityNotDeclared { .. }),
        "{err}"
    );

    let report = broker.capability_report(&id).unwrap();
    let lan_state = report
        .iter()
        .find(|s| s.capability == CapabilityKind::NetLan)
        .unwrap();
    assert_eq!(lan_state.state, GrantState::Revoked);
}

/// Releasing is idempotent and the report reflects it.
#[test]
fn released_grants_leave_the_report() {
    let broker = Broker::new(BrokerPolicy::default());
    let m = manifest("release", r#""compute.cpu" = {}"#);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();
    let g = broker.grant_by_key(&id, "compute.cpu").unwrap();
    broker.release(&id, g.grant_id).unwrap();
    broker.release(&id, g.grant_id).unwrap();
    assert!(!broker.is_live(&id, g.grant_id));
    let report = broker.capability_report(&id).unwrap();
    assert_eq!(report[0].state, GrantState::NotGranted);
    let released = broker
        .audit_log()
        .snapshot()
        .iter()
        .filter(|e| matches!(e, AuditEvent::CapabilityReleased { grant_id, .. } if *grant_id == g.grant_id))
        .count();
    assert_eq!(released, 1, "a second release must not be audited again");
}
