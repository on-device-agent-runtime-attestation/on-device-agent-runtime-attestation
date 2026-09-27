#!/usr/bin/env bash
set -euo pipefail
if ! command -v java >/dev/null 2>&1; then
  echo "SKIP: java not found; skipping model checker"
  exit 0
fi
TLA_JAR="${TLA_JAR:-tools/tla2tools.jar}"
if [[ ! -f "$TLA_JAR" ]]; then
  echo "SKIP: model checker jar not found; skipping model checker"
  exit 0
fi
java -XX:+UseParallelGC -cp "$TLA_JAR" tlc2.TLC -workers auto -config formal/RuntimeAttestation.cfg formal/RuntimeAttestation.tla
