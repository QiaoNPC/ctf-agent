#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEX_ROOT="${SCRIPT_DIR}/codex"
GLOBAL_AGENTS_DIR="${HOME}/.codex/agents"
GLOBAL_SKILLS_DIR="${HOME}/.codex/skills"

if [[ ! -d "${CODEX_ROOT}" ]]; then
  echo "[-] Missing codex directory at: ${CODEX_ROOT}"
  exit 1
fi

mkdir -p "${GLOBAL_AGENTS_DIR}"
mkdir -p "${GLOBAL_SKILLS_DIR}"

echo "[*] Codex root:          ${CODEX_ROOT}"
echo "[*] Global agents dir:   ${GLOBAL_AGENTS_DIR}"
echo "[*] Global skills dir:   ${GLOBAL_SKILLS_DIR}"

# Wipe destination dirs so removed/renamed agents and skills don't linger.
shopt -s dotglob nullglob
for existing_item in "${GLOBAL_AGENTS_DIR}"/*; do
  rm -rf "${existing_item}"
done
for existing_item in "${GLOBAL_SKILLS_DIR}"/*; do
  rm -rf "${existing_item}"
done
shopt -u dotglob nullglob
echo "[*] Cleared existing contents in ${GLOBAL_AGENTS_DIR} and ${GLOBAL_SKILLS_DIR}"

for agent_dir in "${CODEX_ROOT}"/*/; do
  [[ -d "${agent_dir}" ]] || continue

  agent_name="$(basename "${agent_dir}")"
  src_agents="${agent_dir}agents"
  src_skills="${agent_dir}utils/skills"

  if [[ -d "${src_agents}" ]]; then
    shopt -s nullglob
    for agent_md in "${src_agents}"/*.md; do
      cp -a "${agent_md}" "${GLOBAL_AGENTS_DIR}/"
    done
    shopt -u nullglob
    echo "[+] Copied agent markdown for ${agent_name} into ${GLOBAL_AGENTS_DIR}"
  else
    echo "[!] ${agent_name}: no agents folder found"
  fi

  if [[ -d "${src_skills}" ]]; then
    shopt -s dotglob nullglob
    for skill_item in "${src_skills}"/*; do
      cp -a "${skill_item}" "${GLOBAL_SKILLS_DIR}/"
    done
    shopt -u dotglob nullglob
    echo "[+] Copied skills for ${agent_name} into ${GLOBAL_SKILLS_DIR}"
  else
    echo "[!] ${agent_name}: no utils/skills folder found"
  fi
done

echo "[ok] prepare-codex complete."
