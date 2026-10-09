#!/usr/bin/env bash
set -euo pipefail

# Install the CodeQL CLI used by the sdg-extractor query pack.
#
# The bundle unpacks into a durable per-user cache directory and the
# `codeql` binary is symlinked into ~/.local/bin so managed runner
# scripts resolve it through the normal PATH.

version="2.27.2"
install_root="${HOME}/.cache/hyperarm/sdg-extractor/codeql"
bin_dir="${HOME}/.local/bin"
archive="codeql-bundle-cpp-linux64.tar.zst"
# The cpp-only bundle (not the bare CLI zip): it ships the QL packs the
# query pack resolves against, at ${install_root}/qlpacks.
url="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${version}/${archive}"

log() {
  printf '%s\n' "$*" >&2
}

installed_version=""
if [ -x "${install_root}/codeql" ]; then
  installed_version="$("${install_root}/codeql" version 2>/dev/null \
    | sed -n 's/.*release \([0-9.]*\)\..*/\1/p' || true)"
fi

if [ "${installed_version}" = "${version}" ]; then
  log "codeql ${version} already installed at ${install_root}"
else
  if [ -n "${installed_version}" ]; then
    log "upgrading codeql ${installed_version} -> ${version}"
  fi
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT
  log "downloading ${url}"
  curl -fL --retry 3 -o "${tmp_dir}/${archive}" "${url}"
  tar --zstd -xf "${tmp_dir}/${archive}" -C "${tmp_dir}"
  if [ ! -x "${tmp_dir}/codeql/codeql" ]; then
    echo "error: downloaded bundle has no codeql binary" >&2
    exit 1
  fi
  if [ ! -d "${tmp_dir}/codeql/qlpacks" ]; then
    echo "error: downloaded bundle has no qlpacks" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${install_root}")"
  rm -rf "${install_root}"
  mv "${tmp_dir}/codeql" "${install_root}"
  log "installed codeql ${version} at ${install_root}"
fi

if ! "${install_root}/codeql" version >/dev/null 2>&1; then
  echo "error: installed codeql binary is not runnable" >&2
  exit 1
fi

mkdir -p "${bin_dir}"
ln -sfn "${install_root}/codeql" "${bin_dir}/codeql"
log "linked ${bin_dir}/codeql -> ${install_root}/codeql"
