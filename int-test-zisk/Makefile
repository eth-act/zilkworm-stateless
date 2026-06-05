SHELL  = /bin/bash
.SHELLFLAGS = -o pipefail -c

NPROC   := $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu)
PYTHON  := python3
ROOT    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
REPO    := $(ROOT)/..

.PHONY: all guest prover execute prove verify mock-input clean

all: guest prover

# ── Step 1: Build the ZisK C++ guest ELF (rv64ima bare-metal) ────────────────
# Delegates to the repo-root Makefile which runs CMake + ninja/make.
guest:
	$(MAKE) -C $(REPO) guest_zisk
	@echo "Guest ELF: $(REPO)/build/zisk/z6m_guest.elf"

# ── Step 2: Build the Rust ZisK prover host ───────────────────────────────────
# Requires the guest ELF to exist (build.rs will canonicalize the path).
prover: guest
	cargo build --release --manifest-path $(ROOT)/Cargo.toml
	@echo "Prover binary: $(ROOT)/target/release/z6m_zisk_prover"

# ── Test input ────────────────────────────────────────────────────────────────
# Reuses the same mock-input generator as the SP1 integration test.
mock-input:
	$(PYTHON) $(REPO)/int-test/gen_mock_input.py --out $(ROOT)/mock_input.bin
	@echo "Generated: $(ROOT)/mock_input.bin"

# ── Run (emulate only — no proof, instant) ────────────────────────────────────
# Usage:  make execute INPUT=mock_input.bin
execute: prover
	$(ROOT)/target/release/z6m_zisk_prover execute --input $(INPUT)

# ── Prove ─────────────────────────────────────────────────────────────────────
# Usage:  make prove INPUT=mock_input.bin [OUTPUT=proof.bin] [MODE=stark|minimal|plonk]
prove: prover
	$(ROOT)/target/release/z6m_zisk_prover prove \
		--input $(INPUT) \
		--output $(or $(OUTPUT),proof.bin) \
		--mode $(or $(MODE),stark)

# ── Verify ────────────────────────────────────────────────────────────────────
# Usage:  make verify [PROOF=proof.bin]
verify: prover
	$(ROOT)/target/release/z6m_zisk_prover verify \
		--proof $(or $(PROOF),proof.bin)

clean:
	rm -rf $(ROOT)/target
	rm -f  $(ROOT)/mock_input.bin $(ROOT)/proof.bin
