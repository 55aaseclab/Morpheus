"""Recheck saved kernel constraints under an explicit path assumption policy."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

from contracts import CallContracts
from convert_to_sdg import filename, repackage
from path_assumptions import apply_path_assumptions, write_assumption_list
from publication import publication_errors
from semantics import identifier


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def records(path):
    with path.open() as stream:
        next(stream)
        for line in stream:
            if line.startswith("]"):
                break
            yield json.loads(line.rstrip(",\n"))


def recheck(source, output, configuration):
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents:
        raise ValueError("rechecking requires a separate output directory")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "manifest.json").exists():
        raise ValueError("output already contains a completed extraction")
    original = json.loads((source / "manifest.json").read_text())
    if original.get("status") != "success":
        raise ValueError("original extraction is not complete")
    policy = CallContracts(configuration).policy_record()
    old_policy = json.loads((source / "assumption-policy.json").read_text())["policy"]
    if old_policy["contracts"] != policy["contracts"]:
        raise ValueError("saved constraints require unchanged function return contracts")
    nodes = {n["id"]: n for n in json.loads((source / "sdg-nodes.json").read_text())["nodes"]}
    raw_edges = json.loads((source / "sdg-edges.json").read_text())
    edges = {e["id"]: e for e in raw_edges["self_edges"] + raw_edges["cross_edges"]}
    del raw_edges
    exports = {p.name: p.read_text() for p in (source / "runtime-sdg").glob("*.sdg")}
    old_exports, manifests = {}, {}
    for directory in ("sdg", "sdg-conditional", "sdg-unresolved"):
        manifest = json.loads((source / directory / "manifest.json").read_text())
        for record in manifest["rules"]:
            old_exports[record["id"]] = source / directory / record["file"], record
        (output / directory).mkdir(exist_ok=True)
        manifests[directory] = {"version": "1.2", "format": "semantic-sdg", "rules": []}
    coverage = json.loads((source / "analysis-coverage.json").read_text())
    files = {f["file"]: {**f, "source_candidates": Counter(), "sink_candidates": Counter()}
             for f in coverage["files"]}
    statuses, occurrences, transitions = Counter(), Counter(), Counter()
    entries, rule_entries, withheld, admitted_files = {}, {}, [], set()
    counts, published = 0, 0
    last_progress = time.monotonic()
    with (output / "sdg-candidates.json").open("w") as candidates, (output / "sdg-rules.json").open("w") as rules:
        candidates.write('{"version":"1.2","rules":[\n')
        rules.write('{"version":"1.2","rules":[\n')
        for rule in records(source / "sdg-candidates.json"):
            previous = rule["status"]
            if "base_assumption_proof" in rule["validation"]:
                raise ValueError("recheck must start from an extraction before path assumptions")
            apply_path_assumptions(rule, nodes, policy)
            errors = publication_errors(rule, nodes, edges, exports, policy)
            if not errors:
                directory = "sdg"
                if published:
                    rules.write(",\n")
                json.dump(rule, rules, separators=(",", ":"))
                published += 1
                if "file" in rule.get("runtime_export", {}):
                    admitted_files.add(rule["runtime_export"]["file"])
            else:
                withheld.append({"id": rule["id"], "status": rule["status"], "reasons": errors})
                directory = "sdg-unresolved" if rule["status"] == "unresolved" else "sdg-conditional"
            if counts:
                candidates.write(",\n")
            json.dump(rule, candidates, separators=(",", ":"))
            counts += 1
            statuses[rule["status"]] += 1
            transitions[previous + "->" + rule["status"]] += 1
            identities = []
            validation = rule["validation"]
            for entry in validation["assumption_ledger"] + validation["unresolved_prerequisites"]:
                identity = identifier("ledger", json.dumps(entry, sort_keys=True))
                entries[identity] = {"id": identity, "entry": entry}
                identities.append(identity)
                occurrences[entry["kind"] + ":" + entry["status"]] += 1
            rule_entries[rule["id"]] = sorted(set(identities))
            for endpoint in ("source", "sink"):
                name = nodes[rule["path"][endpoint]].get("location", {}).get("file")
                if name in files:
                    files[name][endpoint + "_candidates"][rule["status"]] += 1
            old_file, old_record = old_exports[rule["id"]]
            record = repackage(old_file, output / directory / filename(rule["id"]), old_record, rule)
            manifests[directory]["rules"].append(record)
            if time.monotonic() - last_progress >= 30:
                print(json.dumps({"phase": "recheck", "candidates": counts, "published": published,
                                  "statuses": dict(statuses)}), file=sys.stderr, flush=True)
                last_progress = time.monotonic()
        candidates.write('\n],"count":' + str(counts) + '}\n')
        rules.write('\n],"count":' + str(published) + '}\n')
    for directory, manifest in manifests.items():
        manifest["rules"].sort(key=lambda r: r["id"])
        manifest["count"] = len(manifest["rules"])
        manifest["statuses"] = dict(Counter(r["status"] for r in manifest["rules"]))
        write_json(output / directory / "manifest.json", manifest)
    diagnostics = json.loads((source / "sdg-diagnostics.json").read_text())
    summary = diagnostics["summary"]
    summary.update(assumption_policy=policy, candidates=counts, candidate_statuses=dict(statuses),
                   rules=published, semantic_exports=published, runtime_exports=len(admitted_files),
                   statuses=manifests["sdg"]["statuses"], conditional_exports=manifests["sdg-conditional"]["count"],
                   unresolved_exports=manifests["sdg-unresolved"]["count"], withheld=len(withheld))
    diagnostics["withheld"] = withheld
    write_json(output / "sdg-diagnostics.json", diagnostics)
    write_json(output / "assumption-policy.json", {"version": "1.2", "policy": policy})
    write_json(output / "assumption-ledger.json", {"version": "1.2", "policy_id": policy["id"],
        "candidate_count": counts, "occurrences": dict(occurrences),
        "entries": [entries[k] for k in sorted(entries)], "rule_entries": rule_entries,
        "witness_values": "per-candidate validation.internal_state_witness; never assumed"})
    coverage.update(policy_id=policy["id"], files=[files[k] for k in sorted(files)])
    write_json(output / "analysis-coverage.json", coverage)
    for name in ("sdg-nodes.json", "sdg-edges.json"):
        shutil.copyfile(source / name, output / name)
    (output / "runtime-sdg").mkdir(exist_ok=True)
    for name in admitted_files:
        (output / "runtime-sdg" / name).write_text(exports[name])
    (output / "work").mkdir(exist_ok=True)
    for name in ("facts.csv", "paths.csv", "source-verification.json"):
        shutil.copyfile(source / "work" / name, output / "work" / name)
    write_assumption_list(output)
    (output / "sdg-extractor.log").write_text(
        json.dumps({"phase": "assumption_recheck", "source": str(source),
                    "candidates": counts, "published": published,
                    "transitions": dict(transitions)}, sort_keys=True) + "\n")
    result = {**original, "details": {**original["details"], **summary, "output": str(output),
        "assumption_recheck": {"source": str(source), "transitions": dict(transitions)}}}
    result["artifacts"] = [{"path": item["path"],
        "location": str(output / Path(item["location"]).relative_to(source))}
        for item in original.get("artifacts", original["details"].get("artifacts", []))]
    result["artifacts"].extend({"path": key, "location": str(output / name)} for key, name in (
        ("path-assumptions", "path-assumptions.csv"), ("path-assumptions-report", "path-assumptions.md")))
    result["details"].pop("artifacts", None)
    write_json(output / "manifest.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--assumptions", required=True, type=Path)
    parser.add_argument("--result-file", type=Path)
    args = parser.parse_args()
    result = recheck(args.source, args.output, json.loads(args.assumptions.read_text()))
    if args.result_file:
        write_json(args.result_file, result)
    print(json.dumps(result["details"]["assumption_recheck"]))


if __name__ == "__main__":
    main()
