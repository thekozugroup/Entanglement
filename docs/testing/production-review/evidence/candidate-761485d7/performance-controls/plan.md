# Follow-up to the initial seven-route benchmark

The primary comparison missed six of seven predeclared paired limits. Within individual runs, both the local and remote high-concurrency distributions varied substantially. The tested local and static Iroh routes use the same request handler before and after the Tailscale-specific change. Two additional runs investigate variation and trial order.

1. Run the same full matrix against two copies of the previous reviewed binary, treating the two labels as separate conditions. Verify the daemon hashes are identical. Record cgroup CPU throttling counters around each matrix.
2. Re-run the primary comparison with the candidate first, baseline first, candidate first for greetings, and baseline first for image batches. Use the same data, clients, warmup, sample counts, byte checks and 5% limits. Publish all of these results alongside the primary matrix, regardless of outcome.

These comparisons explain uncertainty and possible order effects. The preregistered primary result remains recorded.
