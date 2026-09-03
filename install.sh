#!/usr/bin/env bash
# install.sh — install Titanis (if needed) + titan wrapper
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
WRAPPER="${BIN_DIR}/titan"

TITANIS_FORK_URL="https://github.com/mattmillen15/Titanis.git"
TITANIS_FORK_BRANCH="tsch"

TITANIS_INSTALL_DIR="${HOME}/tools/titanis"
TITANIS_SRC_DIR="${HOME}/tools/titanis-src"

DOTNET_CHANNEL="9.0"
DOTNET_SDK_VER="9.0.317"

# ── .NET ─────────────────────────────────────────────────────────────────────

DOTNET_ROOT_FOUND=""

find_dotnet() {
    for d in "${DOTNET_ROOT:-}" "${HOME}/.dotnet" "/usr/share/dotnet" "/usr/local/share/dotnet"; do
        [[ -z "${d}" ]] && continue
        if ls "${d}/shared/Microsoft.NETCore.App/" 2>/dev/null | grep -q "^[89]\."; then
            echo "${d}"; return 0
        fi
    done
    return 1
}

find_dotnet_sdk() {
    local root="${1}"
    ls "${root}/sdk/" 2>/dev/null | grep -q "^9\." && return 0
    return 1
}

install_dotnet_sdk() {
    local root="${HOME}/.dotnet"
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64)  arch="x64" ;;
        aarch64) arch="arm64" ;;
    esac
    local url="https://builds.dotnet.microsoft.com/dotnet/Sdk/${DOTNET_SDK_VER}/dotnet-sdk-${DOTNET_SDK_VER}-linux-${arch}.tar.gz"
    local tmp="/tmp/dotnet-sdk-$$.tar.gz"

    echo "[*] Downloading .NET SDK ${DOTNET_SDK_VER}..."
    curl -fLk --progress-bar -o "${tmp}" "${url}"
    mkdir -p "${root}"
    tar xzf "${tmp}" -C "${root}"
    rm -f "${tmp}"
    echo "[+] .NET SDK installed: ${root}"
    DOTNET_ROOT_FOUND="${root}"
}

if DOTNET_ROOT_FOUND="$(find_dotnet)"; then
    echo "[+] .NET runtime: ${DOTNET_ROOT_FOUND}"
fi

ensure_dotnet_sdk() {
    if [[ -n "${DOTNET_ROOT_FOUND}" ]] && find_dotnet_sdk "${DOTNET_ROOT_FOUND}"; then
        return 0
    fi
    install_dotnet_sdk
}

# ── Titanis binaries ─────────────────────────────────────────────────────────

TITANIS_ROOT=""
for candidate in "${TITANIS_PATH:-}" \
                 "${TITANIS_INSTALL_DIR}/linux-x64" \
                 "${REPO_DIR}/../titanis/linux-x64"; do
    [[ -z "${candidate}" ]] && continue
    if [[ -d "${candidate}" ]] && [[ -f "${candidate}/Smb2Client/Smb2Client" ]]; then
        TITANIS_ROOT="${candidate}"
        break
    fi
done

if [[ -z "${TITANIS_ROOT}" ]]; then
    echo "[*] Titanis not found — downloading upstream release..."
    command -v curl  &>/dev/null || { echo "[!] curl required" >&2; exit 1; }
    command -v unzip &>/dev/null || { echo "[!] unzip required" >&2; exit 1; }

    UPSTREAM_URL="https://github.com/trustedsec/Titanis/releases/download/v0.9.262/Titanis-tools-linux-x64-net8.zip"
    TMP_ZIP="/tmp/Titanis-linux-x64-$$.zip"
    curl -fLk --progress-bar -o "${TMP_ZIP}" "${UPSTREAM_URL}"
    mkdir -p "${TITANIS_INSTALL_DIR}"
    unzip -q -o "${TMP_ZIP}" -d "${TITANIS_INSTALL_DIR}"
    rm -f "${TMP_ZIP}"

    while IFS= read -r -d '' f; do
        case "$(basename "${f}")" in *.so|*.dll|*.pdb|*.json|*.xml|*.md|createdump) continue ;; esac
        file "${f}" 2>/dev/null | grep -q "ELF" && chmod +x "${f}"
    done < <(find "${TITANIS_INSTALL_DIR}" -maxdepth 5 -type f -print0)

    TITANIS_ROOT="${TITANIS_INSTALL_DIR}/linux-x64"
    echo "[+] Titanis installed: ${TITANIS_ROOT}"
fi

echo "[+] Titanis root: ${TITANIS_ROOT}"

# ── Build Tsch from fork (MS-TSCH support) ───────────────────────────────────

if [[ ! -f "${TITANIS_ROOT}/Tsch/Tsch" ]]; then
    echo "[*] Tsch not found — building from fork..."
    ensure_dotnet_sdk
    export DOTNET_ROOT="${DOTNET_ROOT_FOUND}"
    export PATH="${DOTNET_ROOT_FOUND}:${PATH}"

    command -v git &>/dev/null || { echo "[!] git required to build Tsch" >&2; exit 1; }

    if [[ -d "${TITANIS_SRC_DIR}/.git" ]]; then
        echo "[*] Updating fork source..."
        git -C "${TITANIS_SRC_DIR}" fetch origin
        git -C "${TITANIS_SRC_DIR}" checkout "${TITANIS_FORK_BRANCH}"
        git -C "${TITANIS_SRC_DIR}" pull origin "${TITANIS_FORK_BRANCH}"
    else
        echo "[*] Cloning fork..."
        git clone -b "${TITANIS_FORK_BRANCH}" "${TITANIS_FORK_URL}" "${TITANIS_SRC_DIR}"
    fi

    echo "[*] Building Tsch..."
    if ! dotnet publish "${TITANIS_SRC_DIR}/tools/rpc/Tsch/Tsch.csproj" \
        -c Release -o "${TITANIS_ROOT}/Tsch" --nologo -v q 2>&1 | \
        grep -v "^$\|warning MSB4011\|warning CS8625\|warning CS0169"; then
        echo "[!] Tsch build had issues, checking output..." >&2
    fi

    if [[ -f "${TITANIS_ROOT}/Tsch/Tsch" ]]; then
        chmod +x "${TITANIS_ROOT}/Tsch/Tsch"
        echo "[+] Tsch built and installed: ${TITANIS_ROOT}/Tsch/Tsch"
    else
        echo "[!] Tsch build failed — check .NET SDK installation" >&2
    fi
else
    echo "[+] Tsch already installed: ${TITANIS_ROOT}/Tsch/Tsch"
fi

# ── Set DOTNET_ROOT if not yet set ───────────────────────────────────────────

if [[ -z "${DOTNET_ROOT_FOUND}" ]]; then
    DOTNET_ROOT_FOUND="$(find_dotnet || echo "${HOME}/.dotnet")"
fi

export DOTNET_ROOT="${DOTNET_ROOT_FOUND}"
export PATH="${DOTNET_ROOT_FOUND}:${PATH}"

# ── titan wrapper ─────────────────────────────────────────────────────────────

mkdir -p "${BIN_DIR}"

cat > "${WRAPPER}" <<WRAPPER_EOF
#!/usr/bin/env bash
export DOTNET_ROOT="${DOTNET_ROOT_FOUND}"
export PATH="${DOTNET_ROOT_FOUND}:\${PATH}"
export TITANIS_PATH="${TITANIS_ROOT}"
exec python3 "${REPO_DIR}/titan.py" "\$@"
WRAPPER_EOF

chmod +x "${WRAPPER}"
echo "[+] Installed: ${WRAPPER}"

for rc in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
    if [[ -f "${rc}" ]] && [[ -w "${rc}" ]] && ! grep -q 'local/bin' "${rc}" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${rc}"
        echo "[+] Added ~/.local/bin to PATH in ${rc}"
    fi
done

echo ""
echo "[+] Done. Restart your shell or run: source ~/.zshrc"
echo ""
echo "    titan dump -h"
echo "    titan shell -h"
echo "    titan schtask -h"
echo "    titan rbcd -h"
