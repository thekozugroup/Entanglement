# Publisher compromise and disclosure rehearsal

On 27 November 2026 UTC, `/root/tailroute` acted as the on-call operator for a private publisher-compromise exercise against Linux candidate `bb70a6193f8879b1feb3e6d3ceb8f2980413ce58`, source `sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab`. The released CLI and daemon were unpacked from the locally verified unsigned archive with SHA-256 `e2538c818ff960801f882001023ba0f3601a821944660cf382dfe6ea0d7c5aa2`. Two disposable identities and one isolated daemon were used. The working files and notice remained local. [Technical record](publisher-rotation-rehearsal.json) · [Run receipt](publisher-rotation-rehearsal.receipt.json)

1. A simulated report identified a specific publisher and signed package. The operator confirmed the installed component was callable, recorded its identifier and component digest, unloaded it, confirmed it disappeared from the live registry and checked that further invocation failed. Existing signed bytes remained available for incident review.
2. The operator revoked local publisher trust and checked that the old package then failed reload with `ENTANGLE-E0101`.
3. A separately generated publisher signed a replacement package. The daemon initially refused it. The operator added the new public key, loaded and invoked the replacement successfully, then verified that loading the old package still failed. The same daemon stayed online throughout recovery.

## Draft internal disclosure

> Exercise only. A report identified a potentially compromised plugin publisher. We recorded the affected package and digest, unloaded it, withdrew publisher trust, and confirmed that the daemon refused to reload the package. We restored service with the replacement publisher key and retested containment for the old package. For a real incident, identify affected deployments and distribute the replacement fingerprint through an authenticated channel. Retain the evidence and update affected operators as triage progresses.

The published response policy targets acknowledgement within three business days, triage within seven, a fix or plan for High/Critical findings within 30, and coordinated disclosure around day 90. The rehearsal exercised local containment and recovery. External delivery, human response times, multi-site trust coordination and public disclosure were outside the exercise. [Security policy](../../../../../SECURITY.md)
