#!/usr/bin/env bash
#
# Build the PR coverage comment (cov-comment.md) from go-test-coverage's
# structured breakdown files, falling back to the raw report if anything is off.
#
# Why breakdown files and not the human report: the breakdown is stable,
# semicolon-delimited data (file;total_statements;covered_statements), so the
# per-file table and totals survive added files, threshold changes, and report
# reformatting. Only the gate verdict (PASS/FAIL) and, on failure, the required
# percentages are read from the report, via small, specific patterns.
#
# Inputs (environment + files in the working directory):
#   REPORT          go-test-coverage report text (already JSON-decoded)
#   pr.breakdown    this PR's per-file coverage   (required)
#   base.breakdown  main's per-file coverage      (optional; absent => no delta)
# Output:
#   cov-comment.md
set -euo pipefail

OUT="cov-comment.md"
REPORT="${REPORT:-}"

# The reader-facing note, identical under every verdict.
note() {
  cat <<'EOF'

> [!NOTE]
> This percentage counts only the **Go unit tests** (the fast tests that run the plugin's code directly). A separate set of **integration tests** also checks the same code by running it against a real Vault and Keycloak, but those can't be measured here, so the code is tested more thoroughly than this number alone suggests.
EOF
}

# A second note, shown only alongside the per-file table: the table is scoped by
# coverage change, not by which files the PR edited.
note_scope() {
  cat <<'EOF'

> [!NOTE]
> Coverage can shift in files the PR didn't edit, so this lists every file whose coverage changed versus `main`.
EOF
}

# Last-resort path: post the raw report so we never drop information or emit a
# broken table if the structured data is missing or unparseable.
fallback() {
  {
    echo "# Coverage"
    echo
    echo '```text'
    printf '%s\n' "$REPORT"
    echo '```'
    note
  } >"$OUT"
  exit 0
}

# Total coverage % (one decimal) for a breakdown file: sum(covered)/sum(total).
total_pct() {
  awk -F';' 'NF==3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { c+=$3; t+=$2 }
             END { if (t>0) printf "%.1f", c*100/t; else printf "0.0" }' "$1"
}

gate_failed() { printf '%s\n' "$REPORT" | grep -qE 'satisfied:.*FAIL'; }

# Need at least the PR breakdown to build anything structured.
[ -s pr.breakdown ] || fallback

pr_total="$(total_pct pr.breakdown)"
have_base=0
[ -s base.breakdown ] && have_base=1
rows="" # populated when the per-file table is emitted; also gates the second note

{
  echo "## Coverage"
  echo
  if gate_failed; then
    # The gate fails on a total-coverage breach, a per-file floor breach, or both.
    # Name whichever happened: the total breach states the overall minimum; the
    # file breach lists each file's current vs required (override-aware), from the
    # report's "below threshold" block.
    total_thr="$(printf '%s\n' "$REPORT" | grep -oE 'Total coverage threshold \([0-9]+%\)' | grep -oE '[0-9]+' | head -1)"
    total_failed=0
    if printf '%s\n' "$REPORT" | grep -qE 'Total coverage threshold.*FAIL'; then total_failed=1; fi
    file_failed=0
    if printf '%s\n' "$REPORT" | grep -qE 'File coverage threshold.*FAIL'; then file_failed=1; fi

    if [ "$total_failed" = 1 ]; then
      echo "**Result:** ❌ This change drops coverage to ${pr_total}%, below the required ${total_thr:-?}% minimum"
    else
      echo "**Result:** ❌ This change leaves one or more files below their required minimum:"
    fi

    if [ "$file_failed" = 1 ]; then
      echo
      if [ "$total_failed" = 1 ]; then echo "These files are also below their required minimum:"; echo; fi
      echo "| File | Current | Required |"
      echo "|------|--------:|--------:|"
      printf '%s\n' "$REPORT" | awk '
        /below threshold:/ { grab=1; next }
        grab && NF==0      { grab=0 }
        grab {
          file=$1; cur=""; req=""; n=0
          for (i=1; i<=NF; i++) if ($i ~ /^[0-9.]+%$/) { n++; if (n==1) cur=$i; req=$i }
          if (file != "" && cur != "" && req != "")
            printf "| `%s` | %s | **%s** |\n", file, cur, req
        }'
    fi
  else
    # Verdict from the delta vs main.
    if [ "$have_base" = 1 ]; then
      base_total="$(total_pct base.breakdown)"
      if [ "$pr_total" = "$base_total" ]; then
        echo "**Result:** ✅ This change keeps coverage at ${pr_total}%"
      elif awk "BEGIN{exit !($pr_total > $base_total)}"; then
        echo "**Result:** ✅ This change increases coverage from ${base_total}% to ${pr_total}%"
      else
        echo "**Result:** ⚠️ This change decreases coverage from ${base_total}% to ${pr_total}%"
      fi
    else
      echo "**Result:** ✅ Coverage is ${pr_total}%"
    fi

    # Per-file table: only files whose coverage changed vs main (needs base).
    if [ "$have_base" = 1 ]; then
      rows="$(awk -F';' '
        FNR==NR { if (NF==3 && $2 ~ /^[0-9]+$/ && $2>0) basec[$1]=$3*100/$2; next }
        NF==3 && $2 ~ /^[0-9]+$/ {
          cur = ($2>0 ? $3*100/$2 : 0)
          if (($1 in basec) == 0) { printf "| `%s` | %.1f%% | — |\n", $1, cur; next }
          if (sprintf("%.1f", cur) != sprintf("%.1f", basec[$1]))
            printf "| `%s` | %.1f%% | %.1f%% |\n", $1, cur, basec[$1]
        }' base.breakdown pr.breakdown)"
      if [ -n "$rows" ]; then
        echo
        echo "| File | This PR | \`main\` |"
        echo "|------|--------:|-------:|"
        printf '%s\n' "$rows"
      fi
    fi
  fi
  note
  if [ -n "$rows" ]; then note_scope; fi
} >"$OUT"
