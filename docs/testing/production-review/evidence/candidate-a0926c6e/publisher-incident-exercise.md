# Publisher incident and disclosure exercise

On 2026-11-27 UTC, `/root/tailroute` acted as the on-call operator for an isolated publisher-compromise rehearsal on Linux with commit `a0926c6ef3471aad01cedd256028437b249ef747` and source `sha256:a2848766dd5b69cf72246e7cba06c95afe1807d2556f00efec115cdd40cdca45`. The local release archive SHA-256 was `3d63abf40ee1d78d222252063d5e92cd75373b12e1f9d7f4b34977c02c282be1`. The operator used independently generated disposable publisher identities and a real running daemon. [Actions and observed decisions](publisher-rotation-rehearsal.json) · [Exercise receipt](publisher-incident-exercise.receipt.json)

1. A simulated private report identified a particular signed plugin and publisher. The operator recorded its component digest, confirmed the package was present and callable, unloaded it, checked its removal from the active registry, and confirmed that invocation failed. The signed bytes stayed available for local incident analysis.
2. The operator removed the publisher from the local keyring. An attempt to reload the old package returned `ENTANGLE-E0101`. A replacement signed under a new identity was initially refused as well.
3. The operator verified the separate replacement public key, added it to the local keyring, loaded the replacement package, and checked the expected output. The original package still returned `ENTANGLE-E0101`. Recovery used the same daemon process.

## Draft internal notice

> Exercise only. A report identified a potentially compromised publisher. We recorded the package and component digest, unloaded the affected installation, and verified withdrawal of publisher trust. Service resumed under the replacement publisher and the retired package remained blocked. In a real event, identify affected installations, provide the replacement fingerprint through an authenticated channel, and inform affected operators how to confirm containment.

The notice was retained locally. The project targets acknowledgement within three business days, triage within seven business days, a fix or plan for High/Critical findings within 30 days, and coordinated disclosure around day 90. Actual messaging, human response times and multi-site recovery remain outside this exercise. [Disclosure policy](../../../../../SECURITY.md) · [Previous independent rehearsal](../candidate-bb70a619/publisher-incident-exercise.md)
