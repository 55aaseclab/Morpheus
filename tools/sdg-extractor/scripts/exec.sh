#!/usr/bin/env bash
set -euo pipefail

main() {
tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${MORPHEUS_SDG_EXTRACTOR_OUTPUT:?}"
result_file="${MORPHEUS_SDG_EXTRACTOR_RESULT_FILE:-${MORPHEUS_SCRIPT_RESULT_FILE:?}}"
python_bin="${MORPHEUS_SDG_EXTRACTOR_PYTHON:-${HOME}/.cache/hyperarm/sdg-extractor/python/bin/python}"
assumptions_file="${MORPHEUS_SDG_EXTRACTOR_ASSUMPTIONS:-${tool_root}/kernel-success-assumptions.json}"
if [[ -n "${MORPHEUS_SDG_EXTRACTOR_PACKAGE_FROM:-}" ]]; then
  mkdir -p "${output_dir}/work"
  snapshot_dir="$(mktemp -d "${output_dir}/work/extractor.XXXXXX")"
  cp "${tool_root}/scripts/"*.py "${snapshot_dir}/"
  "${python_bin}" "${snapshot_dir}/runtime_package.py" \
    --source "${MORPHEUS_SDG_EXTRACTOR_PACKAGE_FROM}" \
    --output "${output_dir}/runtime-package" --result-file "${result_file}"
  cp "${result_file}" "${output_dir}/manifest.json"
  return
fi
"${python_bin}" -c 'import z3'
if [[ -n "${MORPHEUS_SDG_EXTRACTOR_GUIDANCE_FROM:-}" ]]; then
  mkdir -p "${output_dir}/work"
  snapshot_dir="$(mktemp -d "${output_dir}/work/extractor.XXXXXX")"
  mkdir -p "${snapshot_dir}/scripts"
  cp "${tool_root}/scripts/"*.py "${snapshot_dir}/scripts/"
  "${python_bin}" "${snapshot_dir}/scripts/guidance_export.py" \
    --source "${MORPHEUS_SDG_EXTRACTOR_GUIDANCE_FROM}" --output "${output_dir}" \
    --result-file "${result_file}"
  return
fi
if [[ -n "${MORPHEUS_SDG_EXTRACTOR_RECHECK_FROM:-}" ]]; then
  mkdir -p "${output_dir}/work"
  snapshot_dir="$(mktemp -d "${output_dir}/work/extractor.XXXXXX")"
  mkdir -p "${snapshot_dir}/scripts"
  cp "${tool_root}/scripts/"*.py "${snapshot_dir}/scripts/"
  cp "${assumptions_file}" "${snapshot_dir}/assumptions.json"
  "${python_bin}" "${snapshot_dir}/scripts/recheck_assumptions.py" \
    --source "${MORPHEUS_SDG_EXTRACTOR_RECHECK_FROM}" --output "${output_dir}" \
    --assumptions "${snapshot_dir}/assumptions.json" --result-file "${result_file}"
  return
fi
input_list="${MORPHEUS_SDG_EXTRACTOR_BITCODE_LIST:?}"
source_dir="${MORPHEUS_SDG_EXTRACTOR_SOURCE_DIR:?}"
kbuild_dir="${MORPHEUS_SDG_EXTRACTOR_KBUILD_DIR:-}"
codeql_bin="$(command -v "${CODEQL:-codeql}")"
jobs="${MORPHEUS_SDG_EXTRACTOR_JOBS:-4}"
if ! [[ "${jobs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "MORPHEUS_SDG_EXTRACTOR_JOBS must be a positive integer" >&2
  exit 1
fi
work_dir="${output_dir}/work"
db_dir="${MORPHEUS_SDG_EXTRACTOR_DATABASE:-${work_dir}/database}"
target_file="${MORPHEUS_SDG_EXTRACTOR_TARGET_INFO:-${db_dir}/sdg-target.json}"
plan_file="${work_dir}/compile-plan.json"
facts_bqrs="${work_dir}/facts.bqrs"
paths_bqrs="${work_dir}/paths.bqrs"

mkdir -p "${output_dir}" "${work_dir}"
snapshot_dir="$(mktemp -d "${work_dir}/extractor.XXXXXX")"
query_dir="${snapshot_dir}/queries"
script_dir="${snapshot_dir}/scripts"
mkdir -p "${script_dir}"
cp -R "${tool_root}/queries" "${query_dir}"
cp "${tool_root}/scripts/"*.py "${script_dir}/"
analysis_arguments=()
if [[ -n "${MORPHEUS_SDG_EXTRACTOR_SELECTION:-}" ]]; then
  cp "${MORPHEUS_SDG_EXTRACTOR_SELECTION}" "${snapshot_dir}/selection.json"
  analysis_arguments+=(--selection "${snapshot_dir}/selection.json")
fi
if [[ -f "${assumptions_file}" ]]; then
  cp "${assumptions_file}" "${snapshot_dir}/assumptions.json"
  analysis_arguments+=(--assumptions "${snapshot_dir}/assumptions.json")
elif [[ -n "${MORPHEUS_SDG_EXTRACTOR_ASSUMPTIONS:-}" ]]; then
  echo "Configured assumption policy does not exist: ${assumptions_file}" >&2
  exit 1
fi
rm -f "${facts_bqrs}" "${paths_bqrs}" "${output_dir}/manifest.json" "${result_file}"
rm -f "${output_dir}/sdg-nodes.json" "${output_dir}/assumption-policy.json" \
  "${output_dir}/sdg-edges.json" "${output_dir}/sdg-rules.json" \
  "${output_dir}/sdg-diagnostics.json" "${output_dir}/sdg-candidates.json"
: > "${output_dir}/sdg-extractor.log"
printf 'sdg-extractor exec jobs=%s database=%s\n' "${jobs}" "${db_dir}"

if [[ -z "${MORPHEUS_SDG_EXTRACTOR_DATABASE:-}" ]]; then
: "${kbuild_dir:?MORPHEUS_SDG_EXTRACTOR_KBUILD_DIR is required to create a database}"
"${python_bin}" "${script_dir}/compile_sources.py" plan \
  --input-list "${input_list}" --source-root "${source_dir}" \
  --kbuild-dir "${kbuild_dir}" --output-dir "${work_dir}/objects" \
  --output-plan "${plan_file}"

compile_command="$("${python_bin}" - "${python_bin}" "${script_dir}/compile_sources.py" "${plan_file}" "${jobs}" <<'PY'
import shlex
import sys
print(shlex.join([sys.argv[1], sys.argv[2], "compile", "--plan", sys.argv[3], "--jobs", sys.argv[4]]))
PY
)"

"${codeql_bin}" database create "${db_dir}" --language=cpp \
  --source-root="${source_dir}" --threads="${jobs}" \
  --ram=12000 \
  --command="${compile_command}" \
  --overwrite >>"${output_dir}/sdg-extractor.log" 2>&1
"${python_bin}" "${script_dir}/target_info.py" --plan "${plan_file}" --output "${target_file}"
fi

"${python_bin}" "${script_dir}/verify_database.py" \
  --database "${db_dir}" --input-list "${input_list}" --source-root "${source_dir}" \
  > "${work_dir}/source-verification.json"

if [[ -n "${MORPHEUS_SDG_EXTRACTOR_COMPILE_PLAN:-}" ]]; then
  target_file="${work_dir}/sdg-target.json"
  "${python_bin}" "${script_dir}/target_info.py" \
    --plan "${MORPHEUS_SDG_EXTRACTOR_COMPILE_PLAN}" --output "${target_file}"
fi
target_arguments=()
if [[ -f "${target_file}" ]]; then
  cp "${target_file}" "${snapshot_dir}/sdg-target.json"
  target_arguments=(--target-info "${snapshot_dir}/sdg-target.json")
fi

"${codeql_bin}" query run "${query_dir}/sdg/KernelExtract.ql" \
  --database="${db_dir}" --output="${facts_bqrs}" \
  --threads="${jobs}" --ram=12000 \
  >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" query run "${query_dir}/sdg/KernelPaths.ql" \
  --database="${db_dir}" --output="${paths_bqrs}" \
  --threads="${jobs}" --ram=12000 \
  >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" bqrs decode "${facts_bqrs}" --format=csv \
  --output="${work_dir}/facts.csv"
"${codeql_bin}" bqrs decode "${paths_bqrs}" --format=csv \
  --output="${work_dir}/paths.csv"
"${python_bin}" "${script_dir}/assemble_sdg.py" \
  --facts "${work_dir}/facts.csv" --paths "${work_dir}/paths.csv" \
  "${target_arguments[@]}" \
  "${analysis_arguments[@]}" \
  --source-verification "${work_dir}/source-verification.json" \
  --output "${output_dir}"

"${python_bin}" "${script_dir}/runtime_package.py" \
  --source "${output_dir}/sdg" --output "${output_dir}/runtime-package"

"${python_bin}" - "${output_dir}" "${input_list}" "${source_dir}" "${db_dir}" "${result_file}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
verification = json.loads((output / "work/source-verification.json").read_text())
summary = json.loads((output / "sdg-diagnostics.json").read_text())["summary"]
artifacts = {"output-dir": ".", "manifest": "manifest.json", "log-file": "sdg-extractor.log",
             "sdg-rules": "sdg-rules.json", "sdg-nodes": "sdg-nodes.json",
             "sdg-edges": "sdg-edges.json", "sdg-files": "sdg",
             "sdg-manifest": "sdg/manifest.json",
             "sdg-conditional-files": "sdg-conditional",
             "sdg-unresolved-files": "sdg-unresolved",
             "assumption-policy": "assumption-policy.json",
             "assumption-ledger": "assumption-ledger.json", "analysis-coverage": "analysis-coverage.json",
             "path-assumptions": "path-assumptions.csv", "path-assumptions-report": "path-assumptions.md",
             "mutation-hints": "mutation-hints.csv",
             "runtime-sdg-files": "runtime-sdg",
             "sdg-runtime-package": "runtime-package",
             "sdg-diagnostics": "sdg-diagnostics.json", "sdg-candidates": "sdg-candidates.json"}
manifest = {
    "command": "exec",
    "status": "success",
    "summary": "checked kernel source-to-sink constraints",
    "details": {"output": str(output), **verification,
                "source_dir": sys.argv[3], "database": sys.argv[4], **summary},
    "artifacts": [
        {"path": name, "location": str(output / relative)}
        for name, relative in artifacts.items()
    ],
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
Path(sys.argv[5]).write_text(json.dumps(manifest, indent=2) + "\n")
PY
exit 0
}

main "$@"
