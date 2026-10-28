#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

readonly APP_NAME="RUXMSG"
readonly BINARY_NAME="ruxmsg"

readonly SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd -P
)"

readonly INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
readonly CARGO_TOML="${SCRIPT_DIR}/Cargo.toml"
readonly CARGO_LOCK="${SCRIPT_DIR}/Cargo.lock"

STAGED_BINARY=""

# ---------- Presentation ----------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    readonly C_RESET=$'\033[0m'
    readonly C_CYAN=$'\033[1;36m'
    readonly C_GREEN=$'\033[1;32m'
    readonly C_YELLOW=$'\033[1;33m'
    readonly C_RED=$'\033[1;31m'
    readonly C_DIM=$'\033[2m'
else
    readonly C_RESET=""
    readonly C_CYAN=""
    readonly C_GREEN=""
    readonly C_YELLOW=""
    readonly C_RED=""
    readonly C_DIM=""
fi

banner() {
    printf '%b\n' \
        "${C_CYAN}██████╗  ██╗   ██╗ ██╗  ██╗ ███╗   ███╗ ███████╗  ██████╗ " \
        "██╔══██╗ ██║   ██║ ╚██╗██╔╝ ████╗ ████║ ██╔════╝ ██╔════╝ " \
        "██████╔╝ ██║   ██║  ╚███╔╝  ██╔████╔██║ ███████╗ ██║  ███╗" \
        "██╔══██╗ ██║   ██║  ██╔██╗  ██║╚██╔╝██║ ╚════██║ ██║   ██║" \
        "██║  ██║ ╚██████╔╝ ██╔╝ ██╗ ██║ ╚═╝ ██║ ███████║ ╚██████╔╝" \
        "╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝  ╚═════╝ ${C_RESET}"
    printf '\n'
    printf '  %sEncrypted peer-to-peer messaging%s\n' \
        "${C_DIM}" "${C_RESET}"
    printf '  %sRelease build and installation%s\n\n' \
        "${C_DIM}" "${C_RESET}"
}

info() {
    printf '%s==>%s %s\n' "${C_CYAN}" "${C_RESET}" "$*"
}

success() {
    printf '%s[OK]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"
}

warn() {
    printf '%s[WARN]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2
}

die() {
    printf '%s[ERROR]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2
    exit 1
}

cleanup() {
    local status=$?

    if [[ -n "${STAGED_BINARY}" ]]; then
        if [[ -e "${STAGED_BINARY}" || -L "${STAGED_BINARY}" ]]; then
            if [[ -w "$(dirname -- "${STAGED_BINARY}")" ]]; then
                rm -f -- "${STAGED_BINARY}" || true
            elif command -v sudo >/dev/null 2>&1; then
                sudo rm -f -- "${STAGED_BINARY}" || true
            fi
        fi
    fi

    exit "${status}"
}

trap cleanup EXIT

# ---------- Validation ----------

banner

[[ "${EUID}" -ne 0 ]] ||
    die "Do not run this installer as root. Run ./install.sh normally."

[[ "${INSTALL_DIR}" == /* && "${INSTALL_DIR}" != "/" ]] ||
    die "INSTALL_DIR must be an absolute path other than /."

[[ -f "${CARGO_TOML}" ]] ||
    die "Cargo.toml was not found. Run this script from the RUXMSG repository."

[[ -f "${CARGO_LOCK}" ]] ||
    die "Cargo.lock is missing. Commit the lockfile before installing."

command -v cargo >/dev/null 2>&1 ||
    die "Cargo is not installed or is not available on PATH."

command -v rustc >/dev/null 2>&1 ||
    die "rustc is not installed or is not available on PATH."

command -v install >/dev/null 2>&1 ||
    die "The install utility is required."

command -v mktemp >/dev/null 2>&1 ||
    die "mktemp is required."

command -v mv >/dev/null 2>&1 ||
    die "mv is required."

# Resolve the actual compiler host target so the artifact path
# is explicit and this installer does not accidentally cross-compile.
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"

[[ -n "${HOST_TARGET}" ]] ||
    die "Could not determine the Rust host target."

readonly HOST_TARGET
readonly TARGET_DIR="${SCRIPT_DIR}/target"
readonly BINARY_PATH="${TARGET_DIR}/${HOST_TARGET}/release/${BINARY_NAME}"
readonly DESTINATION="${INSTALL_DIR}/${BINARY_NAME}"

# ---------- Build ----------

info "Preparing ${APP_NAME} release"
printf '  Repository : %s\n' "${SCRIPT_DIR}"
printf '  Target     : %s\n' "${HOST_TARGET}"
printf '  Compiler   : %s\n' "$(rustc --version)"
printf '  Cargo      : %s\n' "$(cargo --version)"
printf '  Destination: %s\n\n' "${DESTINATION}"

info "Building optimized release binary"

cargo build \
    --release \
    --locked \
    --bin "${BINARY_NAME}" \
    --target "${HOST_TARGET}" \
    --target-dir "${TARGET_DIR}" \
    --manifest-path "${CARGO_TOML}"

[[ -f "${BINARY_PATH}" && -x "${BINARY_PATH}" ]] ||
    die "The expected executable was not produced: ${BINARY_PATH}"

success "Release build completed"

# ---------- Installation ----------

info "Preparing installation directory"

if [[ ! -d "${INSTALL_DIR}" ]]; then
    if mkdir -p -- "${INSTALL_DIR}" 2>/dev/null; then
        :
    elif command -v sudo >/dev/null 2>&1; then
        sudo install -d -m 755 -- "${INSTALL_DIR}"
    else
        die "Cannot create ${INSTALL_DIR}; install sudo or choose a writable directory."
    fi
fi

[[ -d "${INSTALL_DIR}" ]] ||
    die "Installation destination is not a directory."

# Stage in the destination directory so the final rename stays
# on the same filesystem. Never overwrite the live executable in place.
if [[ -w "${INSTALL_DIR}" ]]; then
    STAGED_BINARY="$(mktemp "${INSTALL_DIR}/.ruxmsg.XXXXXXXX")"
    install -m 755 -- "${BINARY_PATH}" "${STAGED_BINARY}"
    mv -f -- "${STAGED_BINARY}" "${DESTINATION}"
    STAGED_BINARY=""
else
    command -v sudo >/dev/null 2>&1 ||
        die "sudo is required to install into ${INSTALL_DIR}."

    STAGED_BINARY="$(sudo mktemp "${INSTALL_DIR}/.ruxmsg.XXXXXXXX")"
    sudo install -m 755 -- "${BINARY_PATH}" "${STAGED_BINARY}"
    sudo mv -f -- "${STAGED_BINARY}" "${DESTINATION}"
    STAGED_BINARY=""
fi

# ---------- Verification ----------

[[ -x "${DESTINATION}" ]] ||
    die "Installation finished without an executable at ${DESTINATION}."

printf '\n'
success "${APP_NAME} installed successfully"
printf '\n'
printf '  Executable : %s\n' "${DESTINATION}"
printf '  Target     : %s\n' "${HOST_TARGET}"
printf '  Permissions: 755\n'
printf '\n'
printf '  Run       : %sruxmsg%s\n' "${C_GREEN}" "${C_RESET}"
printf '  Verify    : %s\n' "$(command -v ruxmsg 2>/dev/null || printf '%s' "${DESTINATION}")"
printf '\n'
