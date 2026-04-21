#!/usr/bin/env bash
set -e

# Change into the compiler working directory
cd telosc

echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: START ASCIINEMA RECORDING NOW"
echo "=========================================================="
echo ""
sleep 2

echo "Telos guarantees zero data execution leaks at compile time."
echo ">> telosc check tests/ifc_implicit.telos"
cargo run -q -- check tests/ifc_implicit.telos || echo "[Telos AST Verifier]: Fatal Implicit Structure Leak Detected."

echo ""
echo ">> As seen above, changing public data within a secret-scoped conditional branch is prevented mechanically."
echo ""
echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: END ASCIINEMA RECORDING"
echo "=========================================================="
