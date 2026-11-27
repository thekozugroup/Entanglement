# Follow-up performance controls

The first comparison met both limits on one of seven configurations. With identical predecessor binaries on both sides, five of seven configurations passed. With the build order reversed, five of seven passed. Both additional runs used the original workload sizes and byte checks. [Method agreed before the controls](plan.md) · [Identical binaries](identical.json) · [Reversed build order](reversed.json)

Values below are p95 latency change followed by throughput change. Positive latency and negative throughput are worse. Each comparison requires p95 no more than 5% higher and throughput no more than 5% lower.

| Route | Initial A/B | Identical A/A | Reversed A/B |
| --- | ---: | ---: | ---: |
| image local | +50.3% / -19.8% | +11.6% / -12.3% | -5.4% / +6.4% |
| image one_remote | +7.1% / -0.5% | -3.2% / +0.4% | -18.3% / +8.6% |
| image three_remote | +22.1% / -2.3% | +35.1% / -28.2% | +11.2% / -6.4% |
| local / 1 | +1.6% / -5.8% | -19.8% / +8.5% | +2.0% / -4.2% |
| local / 4 | +23.2% / -5.2% | -0.5% / +1.5% | +20.3% / -2.9% |
| remote / 1 | +0.1% / -1.0% | -16.4% / +2.9% | -2.6% / +3.2% |
| remote / 4 | +31.9% / -12.1% | -0.9% / +2.7% | +2.5% / +3.2% |

The local image result reversed direction across the two build orders. Three-remote image throughput and p95 also missed limits when both sides ran the same binary. Four-client local greetings exceeded the p95 limit in both A/B orders and stayed within it in the A/A control. This remains an unresolved observation. These measurements cannot distinguish a repeatable binary performance difference from host scheduling variation on that route.

The workload and server code used by local work dispatch did not change between the releases. Static Iroh dispatch exercised the ordinary listener. The recovery supervisor runs on Tailscale-only listeners. These details narrow where to investigate. They provide no timing guarantee.

The identical and reversed runs each encountered CPU quota throttling in 23 periods. Throttled time totaled 0.472 s and 0.673 s respectively. The VM had five visible CPUs and a four-core quota. The production performance threshold remains unmet.
