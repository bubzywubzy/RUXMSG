#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="RUXMSG"
readonly BINARY_NAME="ruxmsg"
readonly INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
readonly DESTINATION="${INSTALL_DIR}/${BINARY_NAME}"

# Match RUXMSG's default configuration-path resolution.
if [[ "${XDG_CONFIG_HOME:-}" == /* ]]; then
    readonly CONFIG_DIR="${XDG_CONFIG_HOME}/ruxmsg"
else
    readonly CONFIG_DIR="${HOME:?HOME must be set}/.config/ruxmsg"
fi

# ---------- Colors ----------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    readonly RESET=$'\033[0m'
    readonly CYAN=$'\033[1;36m'
    readonly GREEN=$'\033[1;32m'
    readonly YELLOW=$'\033[1;33m'
    readonly RED=$'\033[1;31m'
    readonly DIM=$'\033[2m'
else
    readonly RESET=""
    readonly CYAN=""
    readonly GREEN=""
    readonly YELLOW=""
    readonly RED=""
    readonly DIM=""
fi

# ---------- Output ----------

banner() {
    printf '%b\n' \
        "${CYAN}██████╗  ██╗   ██╗ ██╗  ██╗ ███╗   ███╗ ███████╗  ██████╗ " \
        "██╔══██╗ ██║   ██║ ╚██╗██╔╝ ████╗ ████║ ██╔════╝ ██╔════╝ " \
        "██████╔╝ ██║   ██║  ╚███╔╝  ██╔████╔██║ ███████╗ ██║  ███╗" \
        "██╔══██╗ ██║   ██║  ██╔██╗  ██║╚██╔╝██║ ╚════██║ ██║   ██║" \
        "██║  ██║ ╚██████╔╝ ██╔╝ ██╗ ██║ ╚═╝ ██║ ███████║ ╚██████╔╝" \
        "╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝  ╚═════╝ ${RESET}"
    printf '\n'
    printf '%s  Encrypted peer-to-peer messaging%s\n' "$DIM" "$RESET"
    printf '%s  Release removal utility%s\n\n' "$DIM" "$RESET"
}

info() {
    printf '%s==>%s %s\n' "$CYAN" "$RESET" "$*"
}

success() {
    printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
    printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*" >&2
}

die() {
    printf '%s[ERROR]%s %s\n' "$RED" "$RESET" "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: ./uninstall.sh [MODE]

Modes:
  binary    Remove only the installed executable (default).
  all       Remove the executable and default configuration directory.
  help      Display this help.

Environment:
  INSTALL_DIR      Executable installation directory.
  XDG_CONFIG_HOME Configuration base directory, if absolute.
                   Otherwise, defaults to \$HOME/.config.

Examples:
  ./uninstall.sh
  ./uninstall.sh binary
  ./uninstall.sh all

Storage notes:
  - Configuration defaults to \$XDG_CONFIG_HOME/ruxmsg,
    or \$HOME/.config/ruxmsg when XDG_CONFIG_HOME is unset
    or not absolute.
  - Identity seeds are stored in the operating system's
    credential store, not in the configuration directory.
  - Custom paths supplied through --config are not discovered
    or removed automatically.
  - The repository and build artifacts are never removed.
EOF
}

# ---------- Confirmation ----------

confirm() {
    local prompt="$1"
    local answer=""

    [[ -t 0 && -t 1 ]] ||
        die "Interactive confirmation requires a terminal."

    printf '%s' "$prompt"
    IFS= read -r answer || answer=""

    case "$answer" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------- Validation ----------

validate_target() {
    local target="$1"

    [[ "$target" == /* && "$target" != "/" ]] ||
        die "Refusing unsafe removal path: $target"

    [[ ! -L "$target" ]] ||
        die "Refusing to remove a symbolic link: $target"

    [[ ! -e "$target" || -f "$target" || -d "$target" ]] ||
        die "Refusing unexpected file type: $target"
}

remove_target() {
    local target="$1"
    local parent

    validate_target "$target"

    if [[ ! -e "$target" && ! -L "$target" ]]; then
        warn "Not present; skipping: $target"
        return 0
    fi

    parent="$(dirname -- "$target")"

    # Use elevated permissions only when the current user cannot
    # remove the target through its own permissions.
    if [[ -w "$parent" && -x "$parent" ]]; then
        rm -r -- "$target"
    else
        command -v sudo >/dev/null 2>&1 ||
            die "sudo is required to remove: $target"
        sudo rm -r -- "$target"
    fi

    [[ ! -e "$target" && ! -L "$target" ]] ||
        die "Removal verification failed: $target"

    success "Removed: $target"
}

# ---------- Main ----------

main() {
    local mode="${1:-binary}"
    local -a targets=()

    [[ "$#" -le 1 ]] || die "Specify only one mode."

    [[ "$EUID" -ne 0 ]] ||
        die "Do not run this script as root. Run it normally."

    case "$mode" in
        help|-h|--help)
            usage
            return 0
            ;;
        binary|all)
            ;;
        *)
            usage >&2
            die "Unknown mode: $mode"
            ;;
    esac

    [[ "$INSTALL_DIR" == /* && "$INSTALL_DIR" != "/" ]] ||
        die "INSTALL_DIR must be an absolute path other than /."

    command -v rm >/dev/null 2>&1 ||
        die "Required command not found: rm."

    command -v dirname >/dev/null 2>&1 ||
        die "Required command not found: dirname."

    banner

    info "Removal mode: $mode"
    printf '  Executable: %s\n' "$DESTINATION"

    validate_target "$DESTINATION"
    targets+=("$DESTINATION")

    if [[ "$mode" == all ]]; then
        # The configuration target must be RUXMSG's dedicated
        # default configuration directory, never a broad parent.
        [[ "$CONFIG_DIR" != "$HOME" &&
           "$CONFIG_DIR" != "$HOME/" &&
           "$CONFIG_DIR" != "$HOME/.config" &&
           "$CONFIG_DIR" != "$HOME/.local" &&
           "$CONFIG_DIR" != "$HOME/.ssh" &&
           "$CONFIG_DIR" != "/usr" &&
           "$CONFIG_DIR" != "/usr/local" &&
           "$CONFIG_DIR" != "/etc" &&
           "$CONFIG_DIR" != "/var" &&
           "$CONFIG_DIR" != "/opt" ]] ||
            die "Refusing unsafe configuration directory: $CONFIG_DIR"

        validate_target "$CONFIG_DIR"
        targets+=("$CONFIG_DIR")

        printf '\n%sFULL REMOVAL TARGETS%s\n' "$YELLOW" "$RESET"
        printf '  - %s\n' "${targets[@]}"
        printf '\n'

        warn "The configuration directory may contain user settings."
        warn "Identity credentials in the OS credential store are NOT removed."
        warn "Custom --config paths, repositories, and build artifacts are retained."

        confirm "Permanently remove the listed targets? [y/N] " ||
            { info "Removal cancelled."; return 0; }
    else
        printf '\n'
        printf 'This removes only the installed executable.\n'
        printf 'Configuration, identity credentials, and repository files remain.\n\n'

        confirm "Uninstall ${APP_NAME}? [y/N] " ||
            { info "Removal cancelled."; return 0; }
    fi

    info "Removing installed executable"
    remove_target "$DESTINATION"

    if [[ "$mode" == all ]]; then
        info "Removing default configuration directory"
        remove_target "$CONFIG_DIR"
    fi

    printf '\n'
    success "${APP_NAME} filesystem removal completed."

    if [[ "$mode" == binary ]]; then
        printf '  Removed: executable (if present)\n'
        printf '  Retained: configuration, identity credentials, repository, build artifacts\n'
    else
        printf '  Removed: executable and default configuration directory (if present)\n'
        printf '  Retained: identity credentials, custom config paths, repository, build artifacts\n'
    fi

    printf '\n'
    warn "This script does not erase identity credentials from your OS credential store."
}

main "$@"
