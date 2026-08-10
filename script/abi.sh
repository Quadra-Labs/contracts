#!/usr/bin/env bash
#
# abi.sh — regenerate contracts/abi/*.json from the compiled sources, or check they are in step.
#
# The six files under abi/ are the ONLY description of this contract surface that other repos can
# read: `data`, `agent` and the verify tool each hand-write a slice of it, and a slice that drifts
# from its contract does not fail at build time — it fails at runtime with an opaque decode error,
# or worse, decodes to plausible garbage. Nothing kept those artifacts honest, so this does.
#
#   ./script/abi.sh            regenerate abi/*.json from src/
#   ./script/abi.sh --check    regenerate into a temp dir and fail if anything differs
#
# `--check` is the tripwire: run it after any change to src/ and before any redeploy. It exits
# non-zero and prints a diff, so it works the same by hand as it would in an automated job.
#
# NOTE ON FORMATTING. `forge inspect <Name> abi --json` on foundry 1.7.1 emits exactly the shape
# already committed here — 2-space indent, forge's own key order, trailing newline — so this
# script is a plain redirect with no reformatting step and no `jq` dependency (which is not
# reliably present on a Windows dev box). That was verified byte-for-byte against all six files.
# If a future foundry changes its formatting, `--check` will flap on every file at once rather
# than on one: that pattern means re-record the artifacts, not that the ABIs drifted.
set -euo pipefail

# Only the deployable contracts. Libraries (FtsoLib, TeeActionResult, SignatureLib), the base
# Ownable2Step and the interfaces are deliberately absent: nothing downstream binds to them, and
# an artifact nobody reads is one more thing to keep in step for no benefit.
CONTRACTS=(
    EvaluationInstructionSender
    JobEscrow
    Passport
    QuadraToken
    SealedCompetition
    TeeRegistry
)

cd "$(dirname "$0")/.."

check=false
if [[ "${1:-}" == "--check" ]]; then
    check=true
elif [[ $# -gt 0 ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

# Exit 2 means "the check could not run"; exit 1 means "the check ran and failed". Without the
# distinction a missing toolchain reads as ABI drift, which sends the reader to the wrong place.
# foundryup installs outside the default PATH on Windows, so this is a real first-run failure.
if ! command -v forge >/dev/null 2>&1; then
    echo "abi.sh: forge is not on PATH (foundryup installs to ~/.foundry/bin — add it)" >&2
    exit 2
fi

# One scratch dir and one cleanup hook: a second `trap ... EXIT` would silently replace the first
# and leak whatever the first was holding.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Build first, always. `forge inspect` reads the build output, so without this a --check run can
# pass against a stale artifact from before the edit being checked.
#
# Output is held back rather than streamed: forge's linter prints a page of advisory warnings on
# every build, and a check whose PASS is buried under 200 lines of unrelated noise is a check
# people stop reading. On failure the whole log is shown.

# `--skip test` on purpose. These artifacts describe src/, and the test tree is a local working
# area that other clones may not even have; letting a stale test file fail the compile would block
# regenerating an ABI that is perfectly valid. Run `forge test` separately for that.
if ! forge build --skip test >"$tmp/build.log" 2>&1; then
    cat "$tmp/build.log" >&2
    echo "abi.sh: the build failed, so there is nothing to inspect" >&2
    exit 1
fi

if [[ "$check" == false ]]; then
    for name in "${CONTRACTS[@]}"; do
        # Via a temp file, NOT a redirect straight onto the artifact. The shell truncates a
        # redirect target before the command runs, so `forge inspect` failing — an unknown name, or
        # an ambiguous one like the `ITeeRegistry` declared in two files — would leave the
        # committed artifact zero bytes and `set -e` would abort before anything could restore it.
        forge inspect "$name" abi --json >"$tmp/$name.json"
        mv "$tmp/$name.json" "abi/$name.json"
        echo "wrote abi/$name.json"
    done
    exit 0
fi

drift=0

# --- coverage, before content -----------------------------------------------------------------
#
# The loop below only visits names in CONTRACTS, so on its own it happily reports "in step" while
# a brand-new contract has no artifact at all, or a deleted one leaves an artifact behind still
# advertising a surface that no longer exists. Both are drift; neither involves a byte changing in
# a file the loop reads. So the file set and the source set are asserted first.
#
# `^contract X` matches concrete contracts only: `abstract contract`, `interface` and `library`
# all fail the anchor, which is exactly the set that should have no artifact. Doing it with grep
# rather than by parsing out/ keeps this script dependency-free — contracts/ has no package.json
# and no node_modules, and requiring a JSON parser here would be a new prerequisite for a repo
# that currently needs only foundry.
declared="$(grep -hoE '^contract [A-Za-z0-9_]+' src/*.sol | awk '{print $2}' | sort -u)"
expected="$(printf '%s\n' "${CONTRACTS[@]}" | sort -u)"
if [[ "$declared" != "$expected" ]]; then
    echo "COVERAGE the CONTRACTS list in this script does not match the concrete contracts in src/" >&2
    diff <(echo "$expected") <(echo "$declared") |
        sed -e 's/^</  only in abi.sh:  /' -e 's/^>/  only in src\/:   /' >&2 || true
    echo "  Add or remove the name above, then run ./script/abi.sh to record the change." >&2
    drift=1
fi

present="$(cd abi && ls -1 ./*.json 2>/dev/null | sed -e 's|^\./||' -e 's|\.json$||' | sort -u || true)"
if [[ "$present" != "$expected" ]]; then
    echo "COVERAGE abi/ holds a different set of artifacts than this script generates" >&2
    diff <(echo "$expected") <(echo "$present") |
        sed -e 's/^</  missing from abi\/: /' -e 's/^>/  orphan in abi\/:    /' >&2 || true
    drift=1
fi

# --- content ------------------------------------------------------------------------------------
for name in "${CONTRACTS[@]}"; do
    forge inspect "$name" abi --json >"$tmp/$name.json"
    if [[ ! -f "abi/$name.json" ]]; then
        echo "MISSING  abi/$name.json is not committed" >&2
        drift=1
        continue
    fi
    if ! diff -u "abi/$name.json" "$tmp/$name.json" >"$tmp/$name.diff"; then
        echo "DRIFT    abi/$name.json does not match src/" >&2
        sed -e "s|$tmp/|regenerated: |" -e "s|^--- abi/|committed:   abi/|" "$tmp/$name.diff" >&2
        drift=1
    fi
done

if [[ "$drift" -ne 0 ]]; then
    cat >&2 <<'MSG'

The committed ABI artifacts are out of step with src/. Every downstream consumer reads these,
so run `./script/abi.sh` and review the diff as a deliberate interface change — then refresh the
hand-written copies in data/src/chain/abis.ts, data/packages/verify/src/abis.ts and
agent/app/src/chain/abis.ts, which the artifacts do not update on their own.
MSG
    exit 1
fi

# Say what this did NOT prove. The three hand-written copies downstream are the thing most likely
# to rot, and a bare "in step" here reads as covering them.
echo "abi/ is in step with src/ (${#CONTRACTS[@]} contracts checked)"
echo "note: this does not check the hand-written copies in data/ and agent/ — compare those by hand"
