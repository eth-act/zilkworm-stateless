# Maintainers

## Team

zilkworm-stateless is maintained by the **eth applied cryptography team**,
building on the [zilkworm](https://github.com/developeruche/zilkworm)
stateless-execution engine, itself a fork of
[erigontech/silkworm](https://github.com/erigontech/silkworm) — an
established execution-layer codebase whose upstream is actively maintained
by the Erigon team.

| Area | Where it lives |
|---|---|
| Guest wire contract, per-zkVM runtimes, releases | this repository |
| Stateless execution engine (EVM, MPT, witness ingestion) | `zilkworm` (`zilk_core`) |
| EVM interpreter + precompiles | `zvm1` (evmone fork) |

## Release & spec tracking

- Releases are tag-driven through the public CI in
  `.github/workflows/release.yml`; artifacts are minisign-signed with the
  key published in each release (`minisign.pub`).
- The guest tracks the EF zkEVM canonical wire contract
  (`tests-zkevm@vA.B.C` releases of
  [execution-specs](https://github.com/ethereum/execution-specs)); the
  pinned target and the conformance tooling live in `conformance/`.
- zkVM SDK versions are pinned in `ZKVM_VERSIONS`.

## Security contact

Report security issues privately to the maintainers (see repository owner
profile) rather than via public issues.
