import argparse
import glob
import json
import os
import sys

from core import evaluate


def find_files(paths, recursive):
    for p in paths:
        if os.path.isdir(p):
            pattern = os.path.join(p, "**" if recursive else "", "*.md")
            yield from sorted(glob.glob(pattern, recursive=recursive))
        else:
            yield p


def scan(files, model):
    for path in files:
        try:
            text = open(path, encoding="utf-8").read()
            result = evaluate(text, model=model)
        except Exception as e:
            result = {"verdict": "error", "error": str(e)}
        result["file"] = path
        yield result


def print_report(results):
    for r in results:
        if r["verdict"] == "malicious":
            mark, extra = "MALICIOUS", f" [{r.get('category')}, confidence={r.get('confidence', 0):.2f}]"
        elif r["verdict"] == "error":
            mark, extra = "ERROR", f" ({r.get('error', '')})"
        else:
            mark, extra = "benign", ""
        print(f"[{mark}]{extra} {r['file']}")
        if r["verdict"] == "malicious":
            print(f"    flags: {', '.join(r.get('flags', []))}")
            print(f"    rationale: {r.get('rationale', '')}")

    n = len(results)
    n_bad = sum(1 for r in results if r["verdict"] == "malicious")
    n_err = sum(1 for r in results if r["verdict"] == "error")
    print(f"\n{n} file(s) scanned -- {n_bad} malicious, {n_err} error(s).")


def main():
    ap = argparse.ArgumentParser(description="Scan agent skill files for Semantic Compliance Hijacking (SCH) attacks.")
    ap.add_argument("paths", nargs="+", help="skill file(s) or directory to scan")
    ap.add_argument("--recursive", action="store_true", help="scan directories recursively")
    ap.add_argument("--model", default=None, help="backbone model (default: claude-sonnet-5)")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON instead of a text report")
    args = ap.parse_args()

    files = list(find_files(args.paths, args.recursive))
    if not files:
        print("no files found", file=sys.stderr)
        sys.exit(2)

    results = list(scan(files, args.model))

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_report(results)

    sys.exit(1 if any(r["verdict"] == "malicious" for r in results) else 0)


if __name__ == "__main__":
    main()
