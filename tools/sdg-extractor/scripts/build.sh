#!/usr/bin/env bash
set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${tool_root}/../_shared/scripts/lock.sh"
source "${tool_root}/../_shared/scripts/parallelism.sh"
build_dir="${MORPHEUS_SDG_EXTRACTOR_BUILD_DIR:-${tool_root}/builds/default/build}"
result_file="${MORPHEUS_SDG_EXTRACTOR_RESULT_FILE:-${MORPHEUS_SCRIPT_RESULT_FILE:?}}"
build_dir_key="${MORPHEUS_SDG_EXTRACTOR_BUILD_DIR_KEY:-default}"

morpheus_lock_acquire "${MORPHEUS_SDG_EXTRACTOR_SOURCE:-${tool_root}}.morpheus.lock"
morpheus_build_lock sdg-extractor "${build_dir_key}"
trap morpheus_lock_release EXIT INT TERM

codeql_bin="$(command -v "${CODEQL:-codeql}")"
query_dir="${tool_root}/queries"
python_bin="${MORPHEUS_SDG_EXTRACTOR_PYTHON:-${HOME}/.cache/hyperarm/sdg-extractor/python/bin/python}"
jobs="$(morpheus_default_jobs)"
"${python_bin}" -c 'import z3'
mkdir -p "${build_dir}"

"${codeql_bin}" query compile "${query_dir}/sdg/KernelExtract.ql" \
  "${query_dir}/sdg/KernelPaths.ql" \
  --threads="${jobs}" --ram=6000
"${python_bin}" - "${build_dir}" "${result_file}" <<'PY'
import json
from pathlib import Path
import sys

build = Path(sys.argv[1])
result = {"command": "build", "status": "success",
          "summary": "compiled kernel dependency and semantic fact queries",
          "details": {"build_dir": str(build)},
          "artifacts": [{"path": "build-dir", "location": str(build)}]}
for path in (build / "manifest.json", Path(sys.argv[2])):
    path.write_text(json.dumps(result, indent=2) + "\n")
PY
