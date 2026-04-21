#!/usr/bin/env bash
set -e

cd telosc

echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: START ASCIINEMA RECORDING NOW"
echo "=========================================================="
echo ""
sleep 2

echo "Telos physically lowers the validated blocks into the dual-target ELF and BPF architecture."
echo ">> telosc build tests/e2e_policy.telos"
cargo run -q -- build tests/e2e_policy.telos

echo ""
echo ">> Object generated! The zero-trust payload is now isolated."
echo ""
echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: END ASCIINEMA RECORDING"
echo "=========================================================="
