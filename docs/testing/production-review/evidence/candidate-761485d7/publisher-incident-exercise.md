# Publisher compromise exercise

On 27 November 2026 UTC, `/root/advert` exercised suspected publisher key compromise using the optimized Linux x86-64 archive for commit `761485d7490a56c7215ad958db81949204c74245`, source `sha256:d4bac68175f75abfc6b42773658c9022fd822051ffd1d6b38a58ab78df8c7281`. The archive SHA-256 was `da07d6662bda25c9da80974e81d12a62683173f1f67194d841d83c8536145f8a`. The exercise used one local daemon, temporary operator profiles and two disposable keys. [Run receipt](publisher-rotation-rehearsal.receipt.json) · [Observed events](publisher-rotation-rehearsal.log) · [Replay helper](publisher-rotation-rehearsal.py)

1. The operator confirmed a signed component was loaded and returned the expected response, then treated a simulated private report as suspected publisher key compromise. The receipt identifies the affected version, publisher ID and component digest.
2. The operator unloaded the component, verified that it disappeared from the live registry, and confirmed invocation failed while the signed component bytes remained intact. After removing its publisher key, attempting to reload the same bytes returned `ENTANGLE-E0101`.
3. The operator built and signed the known component under a separately generated identity. The daemon initially refused it. After the operator added the new public key through the keyring, the same daemon loaded the replacement and returned the expected result. The retired package continued to return `ENTANGLE-E0101`.

## Draft internal notice

> Exercise only. We received a simulated report of possible compromise of a plugin publisher key. On the affected installation, we identified the signed package and unloaded it. We removed its publisher trust and verified that the daemon refused to reload it. We restored service with a newly trusted publisher key and verified that the retired package stayed blocked. For a real report, determine the affected publishers, assets and deployments. Share replacement key details through an authenticated channel and document how each operator can verify containment.

The notice was retained locally. The project targets acknowledgement within three business days, triage within seven business days, a fix or detailed plan within 30 days for High or Critical cases, and coordinated disclosure around day 90. Actual delivery, human response times, external stakeholder coordination, cross-node trust propagation and public disclosure remain unverified. [Disclosure policy](../../../../../SECURITY.md)
