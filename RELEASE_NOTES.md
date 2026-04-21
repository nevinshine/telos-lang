# Telos v0.1.0-rc1: Zero-Trust "Policy-As-Code" Anchor

Telos has reached its initial Minimum Viable Product milestone. This release strips the generic vision down into an actionable, deterministically checkable platform directly enforcing zero-data leakage dynamically across kernel bounds.

## Enhancements
- **Formal Command Architecture**: The prototype was explicitly refactored. The standard developer workflow natively supports `telosc new`, `telosc check`, `telosc verify`, and `telosc build`.
- **Mathematical Limitations Documented**: Abstract security promises have been codified into actionable definitions within `THREAT_MODEL.md`.
- **First-Run Reproducible Demos**: To guarantee an frictionless adoption cycle, standard asciinema sequence simulators (`demo_1_ifc.sh`, `demo_2_z3.sh`, `demo_3_bpf.sh`) encapsulate deterministic proof structures out-of-the-box.
- **Full CI Bounding**: Regression integration tests covering strict IFC implicit loops, boundary failures, and correct syntax assignments are executed consistently upon pull-requests via explicit Action parameters.

## Known Limitations
- The host-side application binaries natively mirror standard Linux thread environments. Host execution holds no semantic constraints around dynamic OOM loops.
- `declassify` boundaries represent explicit developer mandates. Cryptographic strength mapping operates upon external assumptions intentionally out-of-bounds toward the actual verifier ruleset.
