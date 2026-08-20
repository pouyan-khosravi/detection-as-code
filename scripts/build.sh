#!/usr/bin/env bash
# Convert every Sigma rule into deployable query artifacts for the Wazuh indexer
# (OpenSearch). Output lands in build/ and is uploaded by the CI build job.
set -euo pipefail

RULES_DIR="detections"
PIPELINE="pipelines/wazuh_windows.yml"
OUT="build"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> Plain Lucene queries"
sigma convert -t opensearch_lucene -p "$PIPELINE" -f default \
    -o "$OUT/queries.lucene.txt" "$RULES_DIR"

echo "==> OpenSearch query DSL"
sigma convert -t opensearch_lucene -p "$PIPELINE" -f dsl_lucene \
    -o "$OUT/queries.dsl.json" "$RULES_DIR"

echo "==> OpenSearch monitor rules"
sigma convert -t opensearch_lucene -p "$PIPELINE" -f monitor_rule \
    -o "$OUT/monitors.json" "$RULES_DIR"

echo "==> SQLite queries (used by the test harness)"
sigma convert -t sqlite -p "$PIPELINE" \
    -o "$OUT/queries.sqlite.txt" "$RULES_DIR"

echo
echo "Artifacts:"
ls -la "$OUT"
