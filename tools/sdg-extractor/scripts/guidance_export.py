"""Publish derived mutation guidance while retaining existing Z3 results."""

import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

from convert_to_sdg import filename, repackage
from guidance import attach_guidance
from publication import publication_errors
from path_evidence import NativePaths


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def records(path):
    with path.open() as stream:
        next(stream)
        for line in stream:
            if line.startswith("]"):
                break
            yield json.loads(line.rstrip(",\n"))


def republish(source, output):
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents:
        raise ValueError("guidance publication requires a separate output directory")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "manifest.json").exists():
        raise ValueError("output is already complete")
    original = json.loads((source / "manifest.json").read_text())
    if original.get("status") != "success":
        raise ValueError("original extraction is not complete")
    nodes = {n["id"]: n for n in json.loads((source / "sdg-nodes.json").read_text())["nodes"]}
    raw_edges = json.loads((source / "sdg-edges.json").read_text())
    edges = {e["id"]: e for e in raw_edges["self_edges"] + raw_edges["cross_edges"]}
    del raw_edges
    native_paths = NativePaths(source / "work" / "paths.csv", nodes)
    source_exports, manifests = {}, {}
    for directory in ("sdg", "sdg-conditional", "sdg-unresolved"):
        manifest = json.loads((source / directory / "manifest.json").read_text())
        for record in manifest["rules"]:
            source_exports[record["id"]] = source / directory / record["file"], record
        (output / directory).mkdir(exist_ok=True)
        manifests[directory] = {"format": "semantic-sdg", "version": "1.2", "rules": []}
    candidate_count, admitted_count = 0, 0
    candidate_statuses, published_statuses, operators, roles = (Counter() for _ in range(4))
    withheld = []
    last_progress = time.monotonic()
    with (output / "sdg-candidates.json").open("w") as candidates, \
            (output / "sdg-rules.json").open("w") as rules, \
            (output / "mutation-hints.csv").open("w", newline="") as index:
        writer = csv.DictWriter(index, fieldnames=["rule", "validation_status", "published", "operator",
            "source", "role", "parameters", "constraint", "export"])
        writer.writeheader()
        candidates.write('{"version":"1.2","rules":[\n')
        rules.write('{"version":"1.2","rules":[\n')
        for rule in records(source / "sdg-candidates.json"):
            evidence = native_paths.evidence(rule)
            if evidence:
                rule["path_evidence"] = evidence
            attach_guidance(rule, nodes, edges)
            # Derivation already ran above; publication independently rebuilds
            # the hints to reject any unsupported or stale metadata.
            errors = publication_errors(rule, nodes, edges, {})
            directory = "sdg"
            if errors:
                withheld.append({"id": rule["id"], "status": rule["status"], "reasons": errors})
                directory = "sdg-unresolved" if rule["status"] == "unresolved" else "sdg-conditional"
            else:
                if admitted_count:
                    rules.write(",\n")
                json.dump(rule, rules, separators=(",", ":"))
                admitted_count += 1
                published_statuses[rule["status"]] += 1
            if candidate_count:
                candidates.write(",\n")
            json.dump(rule, candidates, separators=(",", ":"))
            candidate_count += 1
            candidate_statuses[rule["status"]] += 1
            old_file, old_record = source_exports[rule["id"]]
            path = output / directory / filename(rule["id"])
            manifests[directory]["rules"].append(repackage(old_file, path, old_record, rule))
            for hint in rule["mutation_hint"]:
                operators[hint["operator"]] += 1
                roles[hint["derivation"]["role"]] += 1
                writer.writerow({"rule": rule["id"], "validation_status": rule["status"],
                    "published": not errors, "operator": hint["operator"], "source": hint["var"],
                    "role": hint["derivation"]["role"], "parameters": json.dumps({k:v for k,v in hint.items()
                        if k not in {"operator", "var", "derivation"}}),
                    "constraint": json.dumps(hint["derivation"].get("constraint", {})), "export": str(path)})
            if time.monotonic() - last_progress >= 30:
                print(json.dumps({"phase": "guidance", "candidates": candidate_count,
                    "published": admitted_count, "operators": dict(operators)}), file=sys.stderr, flush=True)
                last_progress = time.monotonic()
        candidates.write('\n],"count":' + str(candidate_count) + '}\n')
        rules.write('\n],"count":' + str(admitted_count) + '}\n')
    for directory, manifest in manifests.items():
        manifest["rules"].sort(key=lambda r:r["id"])
        manifest["count"] = len(manifest["rules"])
        manifest["statuses"] = dict(Counter(r["status"] for r in manifest["rules"]))
        write_json(output / directory / "manifest.json", manifest)
    diagnostics = json.loads((source / "sdg-diagnostics.json").read_text())
    summary = diagnostics["summary"]
    summary.update(rules=admitted_count, semantic_exports=admitted_count, statuses=dict(published_statuses),
        candidates=candidate_count, candidate_statuses=dict(candidate_statuses), withheld=len(withheld),
        publication_threshold="basic", solver="z3", solver_success_required=False, hint_operators=dict(operators), hint_roles=dict(roles),
        conditional_exports=manifests["sdg-conditional"]["count"],
        unresolved_exports=manifests["sdg-unresolved"]["count"])
    diagnostics["withheld"] = withheld
    write_json(output / "sdg-diagnostics.json", diagnostics)
    for name in ("sdg-nodes.json", "sdg-edges.json", "assumption-policy.json", "assumption-ledger.json",
                 "analysis-coverage.json", "path-assumptions.csv", "path-assumptions.md"):
        if (source / name).exists():
            shutil.copyfile(source / name, output / name)
    shutil.copytree(source / "runtime-sdg", output / "runtime-sdg", dirs_exist_ok=True)
    (output / "work").mkdir(exist_ok=True)
    for name in ("facts.csv", "paths.csv", "source-verification.json"):
        shutil.copyfile(source / "work" / name, output / "work" / name)
    (output / "sdg-extractor.log").write_text(json.dumps(summary, sort_keys=True) + "\n")
    details = {**original["details"], **summary, "output": str(output), "guidance_source": str(source)}
    artifacts = [{"path": a["path"], "location": str(output / Path(a["location"]).relative_to(source))}
                 for a in original.get("artifacts", details.pop("artifacts", []))]
    from runtime_package import build_package
    build_package(output / "sdg", output / "runtime-package")
    artifacts = [a for a in artifacts if a["path"] != "sdg-runtime-package"]
    artifacts.append({"path": "sdg-runtime-package", "location": str(output / "runtime-package")})
    artifacts.append({"path": "mutation-hints", "location": str(output / "mutation-hints.csv")})
    result = {"command": "exec", "status": "success", "exit_code": 0,
              "summary": "published mutation guidance with Z3 result records", "details": details, "artifacts": artifacts}
    write_json(output / "manifest.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result-file", type=Path)
    args = parser.parse_args()
    result = republish(args.source, args.output)
    if args.result_file:
        write_json(args.result_file, result)
    print(json.dumps({k:result["details"][k] for k in ("rules", "candidate_statuses", "hint_operators")}))


if __name__ == "__main__": main()
