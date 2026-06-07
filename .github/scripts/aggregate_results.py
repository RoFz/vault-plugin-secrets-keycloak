#!/usr/bin/env python3
"""Aggregate per-leg integration results into one Markdown report.

Reads a directory of per-leg result folders (each produced by one matrix leg and
downloaded as a workflow artifact) and emits a single Markdown report with:

  * a provenance block, the plugin commit under test, and for each leg the exact
    Vault and Keycloak image tags + resolved sha256 digests that were exercised;
  * an operations x version table, every test (plugin operation) as a row, every
    leg as a column, pass/fail per cell;
  * an overall verdict.

Each leg folder must contain:
  results.xml  -- pytest --junit-xml output
  meta.json    -- {"label", "vault_image", "vault_digest",
                   "keycloak_image", "keycloak_digest"}

Used only by CI (the integration-report and release-report jobs). Pure standard
library, so the report job needs no extra dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

PASS = "✅"
FAIL = "❌"
MISSING = "⊘"


@dataclass
class Leg:
    label: str
    meta: dict
    results: dict  # test_id -> "pass" | "fail" | "skip"
    parse_error: str | None = None


def _testsuite(root: ET.Element) -> ET.Element | None:
    return root if root.tag == "testsuite" else root.find("testsuite")


def parse_junit(path: Path) -> tuple[dict, str | None]:
    """Return ({test_id: status}, error_or_None)."""
    try:
        suite = _testsuite(ET.parse(path).getroot())
    except Exception as exc:  # missing or malformed
        return {}, str(exc)
    if suite is None:
        return {}, "no <testsuite> element"

    results: dict[str, str] = {}
    for tc in suite.iter("testcase"):
        module = tc.attrib.get("classname", "").split(".")[-1]
        name = tc.attrib.get("name", "")
        test_id = f"{module}::{name}" if module else name
        if tc.find("failure") is not None or tc.find("error") is not None:
            results[test_id] = "fail"
        elif tc.find("skipped") is not None:
            results[test_id] = "skip"
        else:
            results[test_id] = "pass"
    return results, None


def load_legs(results_dir: Path) -> list[Leg]:
    legs: list[Leg] = []
    for meta_path in sorted(results_dir.glob("*/meta.json")):
        leg_dir = meta_path.parent
        meta = json.loads(meta_path.read_text())
        results, err = parse_junit(leg_dir / "results.xml")
        legs.append(
            Leg(
                label=meta.get("label") or leg_dir.name,
                meta=meta,
                results=results,
                parse_error=err,
            )
        )
    legs.sort(key=lambda leg: leg.label)
    return legs


def render(legs: list[Leg], title: str, commit: str | None, repo_url: str | None, provenance: dict | None = None) -> tuple[str, bool]:
    test_ids = sorted({t for leg in legs for t in leg.results})

    total = failed = 0
    for leg in legs:
        for status in leg.results.values():
            if status in ("pass", "fail"):
                total += 1
                failed += status == "fail"
    ok = failed == 0 and all(leg.parse_error is None for leg in legs)

    out: list[str] = [f"# {title}", ""]
    out.append(f"**Result:** {PASS + ' ' + str(total) + ' checks passed' if ok else FAIL + f' {failed} of {total} checks failed'}")
    if commit:
        short = commit[:12]
        out.append(
            f"**Plugin commit:** [`{short}`]({repo_url}/commit/{commit})"
            if repo_url
            else f"**Plugin commit:** `{short}`"
        )
    if provenance:
        sig = f"{PASS} cosign verified" if provenance.get("cosign_verified") else f"{FAIL} cosign NOT verified"
        out += ["", "## Release artifact", ""]
        out.append(f"- **Tag:** `{provenance.get('tag', '?')}`")
        out.append(f"- **Binary:** `{provenance.get('binary', '?')}`")
        out.append(f"- **SHA-256:** `{provenance.get('sha256', '?')}` (checksum verified)")
        out.append(f"- **Signature:** {sig}")
        out.append(f"  - identity: `{provenance.get('cosign_identity', '?')}`")
        out.append(f"  - issuer: `{provenance.get('cosign_issuer', '?')}`")
    out += ["", "## Versions under test", ""]
    for leg in legs:
        meta = leg.meta
        out.append(f"- **{leg.label}**")
        out.append(f"  - Vault: `{meta.get('vault_image', '?')}` @ `{meta.get('vault_digest', '?')}`")
        out.append(f"  - Keycloak: `{meta.get('keycloak_image', '?')}` @ `{meta.get('keycloak_digest', '?')}`")
        if leg.parse_error:
            out.append(f"  - {MISSING} results unavailable: {leg.parse_error}")

    out += ["", "## Operations × versions", ""]
    out.append("| " + " | ".join(["Operation"] + [leg.label for leg in legs]) + " |")
    out.append("|---|" + "".join(":---:|" for _ in legs))
    for test_id in test_ids:
        cells = [{"pass": PASS, "fail": FAIL}.get(leg.results.get(test_id), MISSING) for leg in legs]
        out.append("| " + " | ".join([f"`{test_id}`"] + cells) + " |")
    out.append("")
    return "\n".join(out) + "\n", ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results_dir", type=Path, help="directory of per-leg result folders")
    ap.add_argument("--title", default="Integration matrix")
    ap.add_argument("--commit", default=None, help="plugin commit SHA under test")
    ap.add_argument("--repo-url", default=None, help="repo URL for linking the commit")
    ap.add_argument("--json-out", type=Path, default=None, help="also write a canonical JSON report")
    ap.add_argument("--provenance", type=Path, default=None, help="verification.json (release artifact: tag, sha256, cosign verdict) for the proof header")
    args = ap.parse_args()

    legs = load_legs(args.results_dir)
    if not legs:
        print(f"No result legs (looked for */meta.json under {args.results_dir})", file=sys.stderr)
        return 1

    provenance = json.loads(args.provenance.read_text()) if args.provenance else None
    markdown, ok = render(legs, args.title, args.commit, args.repo_url, provenance)
    sys.stdout.write(markdown)

    if args.json_out:
        args.json_out.write_text(
            json.dumps(
                {
                    "title": args.title,
                    "commit": args.commit,
                    "ok": ok,
                    "provenance": provenance,
                    "legs": [
                        {"label": leg.label, "meta": leg.meta, "results": leg.results, "parse_error": leg.parse_error}
                        for leg in legs
                    ],
                },
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
