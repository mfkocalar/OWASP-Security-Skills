#!/usr/bin/env bash
# scripts/checkpoint1_install_validate.sh
#
# Phase 5 Checkpoint 1 (PKG-04 / D-01 / D-02): runs `claude plugin validate`,
# temporarily overrides .claude-plugin/marketplace.json's plugin entry source
# to a relative local path, installs the plugin from that local source under
# --scope local, runs the scripted discovery smoke test (`claude plugin
# details` / `claude plugin list --json`), then REVERTS the source override
# before finishing. The revert is registered as a `trap ... EXIT` so it runs
# even if an earlier step fails -- the shipped marketplace.json must never be
# left pointing at the test-time relative-path override (D-01's central
# safety property). All output is teed to a transcript artifact.
#
# Usage:
#   scripts/checkpoint1_install_validate.sh [transcript-path]
#
# Reusable: the same sequence (with the marketplace/plugin identifiers left
# as-is, since the marketplace.json entry keeps its github source once
# reverted) is intended to be re-run at ship time for Checkpoint 2, after
# Phase 5 is pushed -- Checkpoint 2 itself is NOT executed by this script.
#
# Design rules (mirrors scripts/lint_skill_md.py's stdlib-only constraint):
# - No dependencies beyond the `claude` CLI and stdlib python3 (used only for
#   the tiny JSON source-field read/write/revert).
# - Every step prints a clear [PASS]/[FAIL] line to the transcript.
# - `set -euo pipefail` plus the EXIT trap: a hard failure anywhere still
#   guarantees the marketplace.json revert runs before the script exits.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MARKETPLACE_JSON=".claude-plugin/marketplace.json"
PLUGIN_NAME="owasp-security-skills"
MARKETPLACE_NAME="owasp-security-skills"
TRANSCRIPT="${1:-.planning/phases/05-packaging-validation-credibility-polish/05-checkpoint1-transcript.md}"

mkdir -p "$(dirname "$TRANSCRIPT")"

# --- revert-on-exit safety net (D-01's central safety property) -----------
OVERRIDE_APPLIED=0

revert_override() {
  if [ "$OVERRIDE_APPLIED" -eq 1 ]; then
    echo "[INFO] Reverting temporary marketplace.json source override..." | tee -a "$TRANSCRIPT"
    python3 -c "
import json, pathlib
p = pathlib.Path('$MARKETPLACE_JSON')
d = json.loads(p.read_text())
entry = d['plugins'][0]
if '_original_source' in entry:
    entry['source'] = entry.pop('_original_source')
    p.write_text(json.dumps(d, indent=2) + '\n')
"
    OVERRIDE_APPLIED=0
  fi
}

trap 'revert_override' EXIT

step() {
  local desc="$1"
  {
    echo ""
    echo "=== ${desc} ==="
  } | tee -a "$TRANSCRIPT"
}

{
  echo "# Checkpoint 1 install-validation transcript"
  echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo ""
} > "$TRANSCRIPT"

# --- Step 1: schema/frontmatter validation (no source rewrite needed) -----
step "Step 1: claude plugin validate ."
if claude plugin validate . 2>&1 | tee -a "$TRANSCRIPT"; then
  echo "[PASS] plugin validate" | tee -a "$TRANSCRIPT"
else
  echo "[FAIL] plugin validate" | tee -a "$TRANSCRIPT"
  exit 1
fi

# --- Step 2: temporary local-source override (uncommitted, reverted below) -
step "Step 2: temporarily overriding marketplace.json plugin source -> relative path"
python3 -c "
import json, pathlib
p = pathlib.Path('$MARKETPLACE_JSON')
d = json.loads(p.read_text())
entry = d['plugins'][0]
entry['_original_source'] = entry['source']
entry['source'] = '.'
p.write_text(json.dumps(d, indent=2) + '\n')
"
OVERRIDE_APPLIED=1
echo "[PASS] source overridden to relative path '.' (on-disk only, not committed)" | tee -a "$TRANSCRIPT"

# --- Step 3: register the local marketplace (local scope only) ------------
step "Step 3: claude plugin marketplace add . --scope local"
if claude plugin marketplace add . --scope local 2>&1 | tee -a "$TRANSCRIPT"; then
  echo "[PASS] marketplace add" | tee -a "$TRANSCRIPT"
else
  echo "[FAIL] marketplace add" | tee -a "$TRANSCRIPT"
  exit 1
fi

# --- Step 4: install from the local source ---------------------------------
step "Step 4: claude plugin install ${PLUGIN_NAME}@${MARKETPLACE_NAME} --scope local"
if claude plugin install "${PLUGIN_NAME}@${MARKETPLACE_NAME}" --scope local 2>&1 | tee -a "$TRANSCRIPT"; then
  echo "[PASS] plugin install" | tee -a "$TRANSCRIPT"
else
  echo "[FAIL] plugin install" | tee -a "$TRANSCRIPT"
  exit 1
fi

# --- Step 5: scripted discovery smoke test (D-02) ---------------------------
step "Step 5a: claude plugin details ${PLUGIN_NAME}@${MARKETPLACE_NAME}"
claude plugin details "${PLUGIN_NAME}@${MARKETPLACE_NAME}" 2>&1 | tee -a "$TRANSCRIPT"

step "Step 5b: claude plugin list --json"
claude plugin list --json 2>&1 | tee -a "$TRANSCRIPT"

# --- Step 6: revert + assert clean (explicit call; the trap is the ---------
#             guaranteed backstop if any step above failed and exited early)
step "Step 6: reverting override and asserting no diff on marketplace.json"
revert_override
if git diff --quiet "$MARKETPLACE_JSON"; then
  echo "[PASS] REVERT_CLEAN -- git diff --quiet ${MARKETPLACE_JSON} succeeded (no committed change)" | tee -a "$TRANSCRIPT"
else
  echo "[FAIL] ${MARKETPLACE_JSON} still shows a diff after revert" | tee -a "$TRANSCRIPT"
  git diff -- "$MARKETPLACE_JSON" | tee -a "$TRANSCRIPT"
  exit 1
fi

{
  echo ""
  echo "=== Checkpoint 2 (deferred) ==="
  echo "Checkpoint 2 (true github-source install, mfkocalar/OWASP-Security-Skills) is"
  echo "deferred to the ship step, after all Phase 5 commits are pushed (the remote is"
  echo "currently behind local HEAD). NOT run by this script/invocation."
  echo ""
  echo "RESULT: PASS -- Checkpoint 1 gate complete."
} | tee -a "$TRANSCRIPT"
