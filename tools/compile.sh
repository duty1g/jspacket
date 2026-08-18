#!/usr/bin/env bash
set -euo pipefail

OUTDIR="${1:-dist/bin}"
mkdir -p "$OUTDIR"

TOOLS=(tools/src/*.ts)
TOTAL=${#TOOLS[@]}
BUILT=0
FAILED=0

echo "[*] Compiling $TOTAL tools → $OUTDIR/"
echo ""

for src in "${TOOLS[@]}"; do
  name=$(basename "$src" .ts)
  out="$OUTDIR/$name"
  printf "  %-25s" "$name"
  if bun build "$src" --compile --outfile "$out" > /dev/null 2>&1; then
    size=$(du -h "$out" | cut -f1)
    echo "OK  ($size)"
    BUILT=$((BUILT + 1))
  else
    echo "FAIL"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "[*] Done: $BUILT/$TOTAL compiled, $FAILED failed → $OUTDIR/"
