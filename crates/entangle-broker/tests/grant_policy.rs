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
        matches!(&err, BrokerError::CapabilityDeniedByPolicy(r) if r.detail == "net.*"),
        "{err}"
    );
    let err = broker.grant_by_key(&id, "net.wan").unwrap_err();
    assert!(
        matches!(err, BrokerError::CapabilityDeniedByPolicy(_)),
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

/// Every audit event names a custom capability by its manifest key
/// (`custom.telemetry`), so grants, releases, refusals and revocations of
/// the same capability can be correlated by name.
#[test]
fn custom_capabilities_have_one_audit_name() {
    let broker = Broker::new(BrokerPolicy::default());
    let m = manifest("custom", r#""custom.telemetry" = {}"#);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();
    let standing = broker.grant_declared(&id).unwrap();
    let g = broker.grant_by_key(&id, "custom.telemetry").unwrap();
    broker.release(&id, g.grant_id).unwrap();
    broker.revoke(&id, "custom.telemetry").unwrap();
    assert!(broker.grant_by_key(&id, "custom.telemetry").is_err());
    broker.unregister_plugin(&id).unwrap();
    assert_eq!(standing.granted.len(), 1);

    let names: Vec<(&'static str, String)> = broker
        .audit_log()
        .snapshot()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::CapabilityGranted { capability, .. } => {
                Some(("granted", capability.into_owned()))
            }
            AuditEvent::CapabilityReleased { capability, .. } => {
                Some(("released", capability.into_owned()))
            }
            AuditEvent::CapabilityRevoked { capability, .. } => {
                Some(("revoked", capability.into_owned()))
            }
            AuditEvent::CapabilityDenied { capability, .. } => {
                Some(("denied", capability.into_owned()))
            }
            _ => None,
        })
        .collect();
    let want = |what: &'static str| (what, "custom.telemetry".to_owned());
    assert_eq!(
        names,
        vec![
            want("granted"),
            want("granted"),
            want("released"),
            want("revoked"),
            want("denied"),
        ]
    );
}

/// §4.3: every capability's `min_tier` gates it. A manifest whose
/// capability list was extended after validation (its fields are public)
/// cannot smuggle a capability above its tier past the broker: the
/// registration is refused and nothing is ever granted.
#[test]
fn registration_refuses_capabilities_above_the_manifest_tier() {
    let broker = Broker::new(BrokerPolicy::default());
    let mut m = manifest("smuggler", r#""compute.cpu" = {}"#);
    assert_eq!(m.effective_tier, entangle_types::tier::Tier::Networked);
    m.capabilities.push(CapabilityKind::HostDockerSocket);
    let id = m.plugin_id.clone();
    let err = broker.register_plugin(m).unwrap_err();
    assert!(
        matches!(err, BrokerError::TierBelowCapability { .. }),
        "{err}"
    );
    assert!(err.to_string().starts_with("ENTANGLE-E0042"), "{err}");
    assert!(err.to_string().contains("host.docker-socket"), "{err}");
    assert!(broker.declared(&id).is_none(), "nothing was registered");
    assert!(broker
        .grant(&id, &CapabilityKind::HostDockerSocket)
        .is_err());

    // Raising the tiers consistently is a different (tier-5) manifest, and
    // registers.
    let mut m = manifest("honest", r#""compute.cpu" = {}"#);
    m.capabilities.push(CapabilityKind::HostDockerSocket);
    m.declared_tier = entangle_types::tier::Tier::Native;
    m.implied_tier = entangle_types::tier::Tier::Native;
    m.effective_tier = entangle_types::tier::Tier::Native;
    broker.register_plugin(m).unwrap();
}

fn native_manifest(name: &str, caps: &str) -> ValidatedManifest {
    let text = format!(
        r#"
[plugin]
id = "{PUB}/{name}@0.1.0"
version = "0.1.0"
tier = 4
runtime = "native"

[capabilities]
{caps}
"#
    );
    let raw: Manifest = toml::from_str(&text).expect("toml");
    validate(raw).expect("valid manifest")
}

/// A native plugin's OS sandbox grants IP networking as a whole: it cannot
/// keep a `net.lan` grant off the WAN, or a host-limited `net.wan` off the
/// LAN. So when the operator denies either network capability, a native
/// plugin gets neither — otherwise `deny_capabilities = ["net.wan"]` would
/// not stop a native plugin's WAN egress. Wasm plugins, whose rules are
/// per address, keep the other one.
#[test]
fn operator_net_denial_covers_both_net_capabilities_of_a_native_plugin() {
    for (deny, declared) in [
        ("net.wan", r#""net.lan" = {}"#),
        (
            "net.lan",
            r#""net.wan" = { hosts = ["api.example.com:443"] }"#,
        ),
    ] {
        let reg = Registry::new();
        let broker = Broker::new(policy(&[deny])).with_metrics(reg.clone());
        let m = native_manifest("native-net", &format!("\"compute.cpu\" = {{}}\n{declared}"));
        let id = m.plugin_id.clone();
        let net = m
            .capabilities
            .iter()
            .find(|c| c.family().starts_with("net."))
            .unwrap()
            .clone();
        broker.register_plugin(m).unwrap();

        let resolution = broker.grant_declared(&id).unwrap();
        assert_eq!(
            resolution
                .granted
                .iter()
                .map(|g| g.kind.clone())
                .collect::<Vec<_>>(),
            vec![CapabilityKind::ComputeCpu],
            "deny {deny}: a native plugin's {} must not be granted",
            net.key()
        );
        assert_eq!(resolution.denied.len(), 1);
        assert!(
            resolution.denied[0].1.starts_with("ENTANGLE-E0124"),
            "{}",
            resolution.denied[0].1
        );
        let err = broker.grant_by_key(&id, &net.key()).unwrap_err();
        assert!(
            matches!(err, BrokerError::CapabilityDeniedByPolicy(_)),
            "{err}"
        );
        assert_eq!(
            denial_count(&reg, net.family(), "operator_policy"),
            Some(2.0)
        );
        let report = broker.capability_report(&id).unwrap();
        let state = &report.iter().find(|s| s.capability == net).unwrap().state;
        assert!(matches!(state, GrantState::Denied { .. }), "{state:?}");
    }

    // The same denial leaves a wasm plugin its other network capability.
    let broker = Broker::new(policy(&["net.wan"]));
    let m = manifest("wasm-net", r#""net.lan" = {}"#);
    let id = m.plugin_id.clone();
    broker.register_plugin(m).unwrap();
    let resolution = broker.grant_declared(&id).unwrap();
    assert_eq!(resolution.granted.len(), 1);
    assert_eq!(resolution.granted[0].kind, CapabilityKind::NetLan);
}

/// §9.4.1 + §4.6: the per-grant tier check reads the ceiling in force *now*.
/// Lowering it below a registered plugin refuses every new grant
/// (`ENTANGLE-E0127`, reason `tier_ceiling`) and suspends the outstanding
/// ones — not live, nothing to realise — exactly as a revocation would,
/// while they stay recorded until the plugin is unregistered (which
/// releases them, audited). Raising the ceiling back restores them.
#[test]
fn a_lowered_ceiling_refuses_new_grants_and_suspends_outstanding_ones() {
    use entangle_types::tier::Tier;
    let reg = Registry::new();
    let broker = Broker::new(BrokerPolicy::default()).with_metrics(reg.clone());
    let m = manifest("ceiling", CAPS);
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
    let outstanding = broker.snapshot_grants(&id).len();
    assert_eq!(broker.live_grants(&id).len(), outstanding);

    assert_eq!(broker.set_max_tier_allowed(Tier::Sandboxed), Tier::Native);
    let err = broker.grant_by_key(&id, "compute.cpu").unwrap_err();
    assert!(matches!(err, BrokerError::TierCeiling(_)), "{err}");
    assert!(err.to_string().starts_with("ENTANGLE-E0127"), "{err}");
    assert_eq!(denial_count(&reg, "compute.cpu", "tier_ceiling"), Some(1.0));
    assert!(
        broker.check_tier(Tier::Networked).is_err() && broker.check_tier(Tier::Sandboxed).is_ok()
    );
    assert!(!broker.is_live(&id, lan) && !broker.is_live(&id, fetched));
    assert!(broker.live_grants(&id).is_empty(), "nothing to realise");
    assert_eq!(
        broker.snapshot_grants(&id).len(),
        outstanding,
        "suspended, not released"
    );
    let report = broker.capability_report(&id).unwrap();
    assert!(
        report
            .iter()
            .all(|s| matches!(&s.state, GrantState::Denied { reason } if reason.contains("ENTANGLE-E0043"))),
        "{report:?}"
    );

    // Raising the ceiling before the plugin is unloaded restores its grants.
    broker.set_max_tier_allowed(Tier::Native);
    assert!(broker.is_live(&id, lan) && broker.is_live(&id, fetched));
    assert_eq!(broker.live_grants(&id).len(), outstanding);

    // Unregistering (what the kernel's unload does after the drain)
    // releases every grant, audited, lowered ceiling or not.
    broker.set_max_tier_allowed(Tier::Sandboxed);
    broker.unregister_plugin(&id).unwrap();
    let released = broker
        .audit_log()
        .snapshot()
        .iter()
        .filter(|e| matches!(e, AuditEvent::CapabilityReleased { plugin, .. } if *plugin == id))
        .count();
    assert_eq!(released, outstanding);
}
