#!/usr/bin/env bash
# Scaffolds a package under packages/ with a standard layout.
# Usage: ./scripts/scaffold-pkg.sh <name> "<description>"
set -euo pipefail

NAME="${1:?usage: scaffold-pkg.sh <name> <description>}"
DESC="${2:?description required}"
DIR="packages/${NAME}"
if [ -d "$DIR" ]; then echo "exists: $DIR"; exit 0; fi

mkdir -p "$DIR/src"

cat > "$DIR/package.json" <<JSON
{
  "name": "@impacket/${NAME}",
  "version": "0.1.0",
  "description": "${DESC}",
  "license": "SEE LICENSE IN ../../LICENSE",
  "type": "module",
  "main": "./src/index.ts",
  "module": "./src/index.ts",
  "types": "./src/index.ts",
  "exports": {
    ".": {
      "types": "./src/index.ts",
      "import": "./src/index.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "test": "vitest run"
  }
}
JSON

cat > "$DIR/tsconfig.json" <<JSON
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "declarationDir": "./dist"
  },
  "include": ["src/**/*"]
}
JSON

cat > "$DIR/src/index.ts" <<TS
// ${DESC}
export const VERSION = '0.1.0';
TS

cat > "$DIR/README.md" <<MD
# @impacket/${NAME}

${DESC}
MD

echo "created $DIR"