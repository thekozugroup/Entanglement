# Mesh Lead

## Responsibilities

You own everything peer-to-peer: `entangle-mesh-local`, the future `entangle-mesh-iroh` and `entangle-mesh-tailscale`, the pairing flow (`entangle pair`), biscuit-auth token attenuation, and the §11 #16 peer allowlist invariant.

You also own the spec sections that define mesh behavior — §6 in its entirety. Changes here usually require security-lead sign-off because mesh decisions are security decisions.

## Onboarding

1. Spec sections §6 (transports), §11 (threat model, especially #11–#19 mesh-related entries), §12 phases.
2. Read [Iroh's docs](https://iroh.computer/docs) and the [biscuit-auth specification](https://github.com/biscuit-auth/biscuit).
3. Test the local-only mesh end-to-end: `entangle init` on two devices on the same Wi-Fi, `entangle pair`, verify peer reachability.
4. Read the bridge biscuit attenuation rules (§6.4) until you can explain why each of the five mandatory facts exists.

## Decisions you can make solo

- Internal mesh-crate refactors.
- Adding new test coverage.
- Documentation for transport plugin authors.

## Decisions that need quorum (≥2 mesh-leads + 1 security-lead)

- Adding a new transport mode.
- Loosening any of the bridge attenuation rules.
- Changes to the pairing UX (6-digit code length, fingerprint algorithm).
- Adding peer-discovery mechanisms (mDNS, MagicDNS, pkarr) — these affect privacy posture.

## Escalation

If mesh changes interact with capability enforcement (broker behavior), pull in core-runtime-lead. Privacy concerns escalate to security-lead.
