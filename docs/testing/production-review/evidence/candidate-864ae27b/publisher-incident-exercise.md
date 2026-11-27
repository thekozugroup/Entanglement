# Publisher compromise rehearsal

This local exercise uses a newly generated disposable publisher identity, the signed hello-world component, a separate replacement publisher and an isolated Linux profile. The signal is a private report of suspected key compromise. No real key or customer data is involved.

## Triage and containment

Identify the published component by its fully qualified publisher, name, version and artifact digest. Treat other components signed by that key as potentially affected. Unload the affected component and remove the publisher's key from the running node. Confirm that loading the old signed package returns `ENTANGLE-E0101`. Repeat the containment on every affected node in an actual incident. The rehearsal covers one installation.

## Recovery

Generate a replacement identity, rebuild and sign the known fixture, and show that the unfamiliar replacement also fails the trust check. Provision its public key through the operator's keyring. Confirm the fresh component returns the expected response, then confirm the old package still fails to load. The harness holds one daemon process open across containment and recovery. The JSON log records elapsed times and public identifiers.

## Disclosure drill

The exercise coordinator drafted the following internal notice. It was retained locally. The maintainer response targets in SECURITY.md are acknowledgement within three business days, triage within seven business days, a fix or detailed plan within thirty days for high or critical reports, and coordinated disclosure at ninety days.

> In this exercise we received a report that a plugin publisher key may be compromised. The operator identified its installed package, unloaded it and removed the publisher's key. An attempt to reload the affected package was denied. The operator restored the service with a separately generated signing key. The old publisher remained blocked. An actual notice would identify the affected publisher and versions, provide the replacement key through an authenticated channel, and explain how operators can verify containment.

External mailbox delivery, human triage, maintainer quorum and public disclosure were outside this local exercise. No independent human audit or response time is claimed. Keep the separately attributed security review and its open findings with the technical receipt when assessing the production gate.
