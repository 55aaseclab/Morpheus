#!/usr/bin/env bash
set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${MORPHEUS_SDG_EXTRACTOR_OUTPUT:?}"
result_file="${MORPHEUS_SDG_EXTRACTOR_RESULT_FILE:-${MORPHEUS_SCRIPT_RESULT_FILE:?}}"
input_list="${MORPHEUS_SDG_EXTRACTOR_BITCODE_LIST:?}"
source_dir="${MORPHEUS_SDG_EXTRACTOR_SOURCE_DIR:?}"
kbuild_dir="${MORPHEUS_SDG_EXTRACTOR_KBUILD_DIR:?}"
codeql_bin="$(command -v "${CODEQL:-codeql}")"
codeql_dist="$(cd "$(dirname "$(readlink -f "${codeql_bin}")")/.." && pwd)"
query_dir="${tool_root}/queries"
work_dir="${output_dir}/work"
db_dir="${work_dir}/database"
plan_file="${work_dir}/compile-plan.json"
facts_bqrs="${work_dir}/facts.bqrs"
paths_bqrs="${work_dir}/paths.bqrs"
bounds_bqrs="${work_dir}/bounds.bqrs"

mkdir -p "${output_dir}" "${work_dir}"
rm -rf "${db_dir}"
rm -f "${facts_bqrs}" "${paths_bqrs}"
: > "${output_dir}/sdg-extractor.log"

python3 "${tool_root}/scripts/compile_sources.py" plan \
  --input-list "${input_list}" --source-root "${source_dir}" \
  --kbuild-dir "${kbuild_dir}" --output-dir "${work_dir}/objects" \
  --output-plan "${plan_file}"

"${codeql_bin}" database create "${db_dir}" --language=cpp \
  --source-root="${source_dir}" --threads="${MORPHEUS_SDG_EXTRACTOR_JOBS:-1}" \
  --ram=12000 \
  --command="python3 ${tool_root}/scripts/compile_sources.py compile --plan ${plan_file} --jobs ${MORPHEUS_SDG_EXTRACTOR_JOBS:-1}" \
  --overwrite >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" query run "${query_dir}/sdg/KernelExtract.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --database="${db_dir}" --output="${facts_bqrs}" \
  --threads="${MORPHEUS_SDG_EXTRACTOR_JOBS:-1}" --ram=12000 \
  >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" query run "${query_dir}/sdg/KernelPaths.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --database="${db_dir}" --output="${paths_bqrs}" \
  --threads="${MORPHEUS_SDG_EXTRACTOR_JOBS:-1}" --ram=12000 \
  >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" query run "${query_dir}/sdg/KernelBounds.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --database="${db_dir}" --output="${bounds_bqrs}" \
  --threads="${MORPHEUS_SDG_EXTRACTOR_JOBS:-1}" --ram=12000 \
  >>"${output_dir}/sdg-extractor.log" 2>&1

"${codeql_bin}" bqrs decode "${facts_bqrs}" --format=csv \
  --output="${work_dir}/facts.csv"
"${codeql_bin}" bqrs decode "${paths_bqrs}" --format=csv \
  --output="${work_dir}/paths.csv"
"${codeql_bin}" bqrs decode "${bounds_bqrs}" --format=csv \
  --output="${work_dir}/bounds.csv"

python3 "${tool_root}/scripts/assemble_sdg.py" \
  --facts "${work_dir}/facts.csv" --paths "${work_dir}/paths.csv" \
  --bounds "${work_dir}/bounds.csv" \
  --source-root "${source_dir}" \
  --output "${output_dir}"

python3 - "${output_dir}" "${input_list}" "${source_dir}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
input_count = len([line for line in Path(sys.argv[2]).read_text().splitlines() if line.strip()])
manifest = {
    "command": "exec",
    "status": "success",
    "summary": "extracted SDG facts from unified kernel database",
    "details": {"output": str(output), "input_count": input_count,
                "source_dir": sys.argv[3], "database": "work/database"},
    "artifacts": [
        {"path": name, "location": str(output / name)}
        for name in ("manifest.json", "sdg-rules.json", "sdg-nodes.json",
                     "sdg-edges.json", "sdg-extractor.log", "sdg")
    ],
}
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(output / "result.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
