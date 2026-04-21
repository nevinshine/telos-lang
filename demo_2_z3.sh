#!/usr/bin/env bash
set -e

cd telosc

echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: START ASCIINEMA RECORDING NOW"
echo "=========================================================="
echo ""
sleep 2

echo "Telos hooks into Microsoft Z3 to formally verify Linux bounds."
echo ">> telosc verify tests/loops_pass.telos"
cargo run -q -- verify tests/loops_pass.telos

echo ""
echo ">> Z3 evaluated every single basic block and execution pathway and mathematically proved the BPF bounds comply with Linux."
echo ""
echo "=========================================================="
echo "🎥 [ACTION REQUIRED]: END ASCIINEMA RECORDING"
echo "=========================================================="
