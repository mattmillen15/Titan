#!/usr/bin/env bash
# install.sh — install titan to ~/.local/bin/titan
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
WRAPPER="${BIN_DIR}/titan"

# Discover DOTNET_ROOT
if [[ -n "${DOTNET_ROOT:-}" ]] && [[ -d "${DOTNET_ROOT}/shared" ]]; then
    DOTNET_ROOT_FOUND="${DOTNET_ROOT}"
elif [[ -f /etc/dotnet/install_location ]]; then
    loc="$(cat /etc/dotnet/install_location)"
    if [[ -d "${loc}/shared" ]]; then
        DOTNET_ROOT_FOUND="${loc}"
    fi
fi
if [[ -z "${DOTNET_ROOT_FOUND:-}" ]]; then
    for candidate in "${HOME}/.dotnet" "/usr/share/dotnet" "/usr/local/share/dotnet"; do
        if [[ -d "${candidate}/shared" ]]; then
            DOTNET_ROOT_FOUND="${candidate}"
            break
        fi
    done
fi
if [[ -z "${DOTNET_ROOT_FOUND:-}" ]]; then
    echo "[!] Could not locate a .NET runtime (no shared/ directory found)." >&2
    echo "    Install .NET 8+ or set DOTNET_ROOT before running this script." >&2
    exit 1
fi
echo "[+] DOTNET_ROOT: ${DOTNET_ROOT_FOUND}"

# Discover Titanis root
TITANIS_ROOT=""
for candidate in "${HOME}/tools/titanis/linux-x64" \
                 "${REPO_DIR}/../titanis/linux-x64" \
                 "${TITANIS_PATH:-}"; do
    if [[ -n "${candidate}" ]] && [[ -d "${candidate}" ]]; then
        TITANIS_ROOT="${candidate}"
        break
    fi
done
if [[ -z "${TITANIS_ROOT}" ]]; then
    echo "[!] Titanis binaries not found." >&2
    echo "    Set TITANIS_PATH to the linux-x64 directory and re-run." >&2
    exit 1
fi
echo "[+] Titanis root: ${TITANIS_ROOT}"

# Create ~/.local/bin if needed
mkdir -p "${BIN_DIR}"

# Write wrapper
cat > "${WRAPPER}" <<WRAPPER_EOF
#!/usr/bin/env bash
export DOTNET_ROOT="${DOTNET_ROOT_FOUND}"
export PATH="${DOTNET_ROOT_FOUND}:\${PATH}"
export TITANIS_PATH="${TITANIS_ROOT}"
exec python3 "${REPO_DIR}/titan.py" "\$@"
WRAPPER_EOF

chmod +x "${WRAPPER}"
echo "[+] Installed: ${WRAPPER}"

# Ensure ~/.local/bin is on PATH in shell rc files
for rc in "${HOME}/.zshrc" "${HOME}/.bashrc"; do
    if [[ -f "${rc}" ]] && [[ -w "${rc}" ]] && ! grep -q 'local/bin' "${rc}" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${rc}"
        echo "[+] Added ~/.local/bin to PATH in ${rc}"
    fi
done

echo ""
echo "[+] Installation complete."
echo "    You may need to restart your shell or run:  source ~/.zshrc"
echo ""
echo "    Quick smoke test:"
echo "      titan dump -h"
echo "      titan shell -h"
echo "      titan rbcd -h"
