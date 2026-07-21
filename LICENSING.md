# Licensing — status and the rubric scope question

## Status

- This repository's own code (`core/`, `zkvm/`, `conformance/`, `keygen/`,
  the int-tests) is dual-licensed **MIT OR Apache-2.0** (`LICENSE-MIT`,
  `LICENSE-APACHE`), with per-file SPDX headers.
- Contributor set at the time of relicensing is small and traceable in git
  history; obtain explicit sign-off from each before external contributions
  grow the set.
- The dependency audit table lives in `README.md` (all redistribution-clean).

## The scope question for the EF zkEVM team (send before investing further)

The rubric requires the guest program repository be MIT + Apache-2.0
dual-licensed. This repository's own code complies. However, the execution
engine the guest links (`zilkworm`/`zilk_core`, a fork of
erigontech/silkworm, and `zvm1`, a fork of ethereum/evmone) is
**Apache-2.0-only** by its upstream authors, and cannot be unilaterally
relicensed MIT by us.

Proposed wording to send:

> For the licensing requirement ("guest program repositories must be
> dual-licensed MIT + Apache-2.0"): does the requirement's scope cover
> (a) the guest repository's own code — the wire contract, runtimes, and
> release tooling — with engine dependencies keeping their upstream
> licenses (here: Apache-2.0 silkworm/evmone forks, consumed as ordinary
> dependencies), or (b) the entire linked source tree including forked
> engine code? Under (a) we comply today. Under (b) we would need
> erigontech's and the evmone authors' agreement to relicense their code,
> or an explicit exception — please confirm which reading is intended and
> whether Apache-2.0-only engine dependencies are acceptable.

Record the written answer here when received.

## Notes

- Apache-2.0 → MIT+Apache-2.0 consumers: Apache-2.0 code can be *used* by
  a dual-licensed project without relicensing; the dual license applies to
  our code, Apache-2.0 to theirs. This is the normal reading (a).
- The GCC toolchain (xPack) is build-time only; the GCC runtime-library
  exception covers `libgcc`/`libstdc++` bits linked into the ELFs.
