#!/usr/bin/env bash
set -euo pipefail

tool_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${tool_root}/../_shared/scripts/lock.sh"
build_dir="${MORPHEUS_SDG_EXTRACTOR_BUILD_DIR:-${tool_root}/builds/default/build}"
result_file="${MORPHEUS_SDG_EXTRACTOR_RESULT_FILE:-${MORPHEUS_SCRIPT_RESULT_FILE:?}}"
build_dir_key="${MORPHEUS_SDG_EXTRACTOR_BUILD_DIR_KEY:-default}"

morpheus_lock_acquire "${MORPHEUS_SDG_EXTRACTOR_SOURCE:-${tool_root}}.morpheus.lock"
morpheus_build_lock sdg-extractor "${build_dir_key}"
trap morpheus_lock_release EXIT INT TERM

codeql_bin="$(command -v "${CODEQL:-codeql}")"
codeql_dist="$(cd "$(dirname "$(readlink -f "${codeql_bin}")")/.." && pwd)"
query_dir="${tool_root}/queries"
mkdir -p "${build_dir}"

"${codeql_bin}" query compile "${query_dir}/sdg/KernelExtract.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --output="${build_dir}/KernelExtract.qlx"
"${codeql_bin}" query compile "${query_dir}/sdg/KernelPaths.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --output="${build_dir}/KernelPaths.qlx"
"${codeql_bin}" query compile "${query_dir}/sdg/KernelBounds.ql" \
  --search-path="${codeql_dist}/qlpacks:${query_dir}" \
  --output="${build_dir}/KernelBounds.qlx"

cat > "${build_dir}/manifest.json" <<EOF
{"command":"build","status":"success","summary":"compiled unified SDG CodeQL queries","details":{"build_dir":"${build_dir}"}}
EOF
cat > "${result_file}" <<EOF
{"summary":"compiled unified SDG CodeQL queries","details":{"build_dir":"${build_dir}"},"artifacts":[{"path":"build-dir","location":"${build_dir}"}]}
EOF
