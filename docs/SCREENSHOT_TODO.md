# Screenshot TODO

The repo's lab card on michaelwong.life requires `docs/screenshot.png`:
- 16:9 aspect ratio
- minimum 1600 × 900 px
- maximum 2 MB
- a real product/UI screenshot (no placeholders, no AI-generated art)

For Entanglement, the obvious choice is a clean terminal recording showing:
1. `entangle init --non-interactive` (shows the wizard output)
2. `entangle plugins load examples/hash-it/dist/`
3. `entangle plugins invoke <id> --input "hello"` (shows the BLAKE3 output)
4. `entangle doctor` (shows the structured check list)

Render via Apple Terminal screenshot or `asciinema` → `agg` → PNG conversion at 1600×900.

Drop the final image at `docs/screenshot.png` and commit. The README and the lab card will pick it up automatically.
