SHELL  = /bin/bash
.SHELLFLAGS = -o pipefail -c

NPROC := $(shell nproc 2>/dev/null || sysctl -n hw.logicalcpu)
ROOT  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

.PHONY: all guest_sp1 guest_zisk guest_risc0 test test-build clean

all: guest_sp1 guest_zisk guest_risc0

# ── SP1 guest (rv64im bare-metal ELF) ────────────────────────────────────────
guest_sp1:
	cmake -S $(ROOT)/zkvm/sp1 -B $(ROOT)/build/sp1 \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/sp1/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/sp1 -j$(NPROC)

# ── RISC0 guest (rv32im bare-metal ELF) ──────────────────────────────────────
guest_risc0:
	cmake -S $(ROOT)/zkvm/risc0 -B $(ROOT)/build/risc0 \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/risc0/cmake/riscv32im-risc0.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/risc0 -j$(NPROC)

# ── ZisK guest (rv64ima bare-metal ELF) ──────────────────────────────────────
guest_zisk:
	cmake -S $(ROOT)/zkvm/zisk -B $(ROOT)/build/zisk \
		-DCMAKE_TOOLCHAIN_FILE=$(ROOT)/zkvm/zisk/cmake/riscv64ima-zisk.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/zisk -j$(NPROC)

# ── EF blockchain test suite (native x86_64) ──────────────────────────────────
test-build:
	cmake -S $(ROOT)/tests -B $(ROOT)/build/tests \
		-DCMAKE_BUILD_TYPE=Release
	cmake --build $(ROOT)/build/tests -j$(NPROC)

# Run all BlockchainTests (GeneralStateTests + ValidBlocks + InvalidBlocks)
test: test-build
	$(ROOT)/build/tests/z6m_test \
		$(ROOT)/tests/ethereum-tests/BlockchainTests

# Run a specific sub-directory of tests, e.g.: make test-only SUITE=GeneralStateTests/stExample
test-only: test-build
	$(ROOT)/build/tests/z6m_test \
		$(ROOT)/tests/ethereum-tests/BlockchainTests \
		$(SUITE)

clean:
	rm -rf $(ROOT)/build
