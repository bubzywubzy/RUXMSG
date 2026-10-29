#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly APP_NAME="RUXMSG"
readonly BINARY_NAME="ruxmsg"

# Resolve components one at a time: normalize dot segments and follow existing
# symlinked directories before safety checks are performed.
normalize_path() {
    local path="$1"
    local current="/"
    local component
    local candidate
    local -a parts=()

    [[ "$path" == /* ]] || return 1
    IFS='/' read -r -a parts <<< "$path"
    for component in "${parts[@]}"; do
        case "$component" in
            ""|.) continue ;;
            ..) current="$(dirname -- "$current")" ;;
            *)
                candidate="${current%/}/${component}"
                if [[ -d "$current" && -d "$candidate" ]]; then
                    current="$(cd -P -- "$candidate" && pwd -P)"
                else
                    current="$candidate"
                fi
                ;;
        esac
    done
    printf '%s\n' "$current"
}

INSTALL_DIR="$(normalize_path "${INSTALL_DIR:-/usr/local/bin}")" || {
    printf '[ERROR] INSTALL_DIR must resolve from an absolute path.\n' >&2
    exit 1
}
readonly INSTALL_DIR
readonly DESTINATION="${INSTALL_DIR}/${BINARY_NAME}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    readonly RESET=$'\033[0m' CYAN=$'\033[1;36m' GREEN=$'\033[1;32m'
    readonly YELLOW=$'\033[1;33m' RED=$'\033[1;31m'
else
    readonly RESET="" CYAN="" GREEN="" YELLOW="" RED=""
fi

info() { printf '%s==>%s %s\n' "$CYAN" "$RESET" "$*"; }
success() { printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() { printf '%s[ERROR]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./scripts/uninstall.sh [binary|all] [--dry-run]

Modes:
  binary       Remove only the installed executable (default).
  all          Also remove RUXMSG's default configuration directory.

Options:
  --dry-run    Show validated targets without changing files or prompting.
  -h, --help   Show this help.

Environment:
  INSTALL_DIR      Executable installation directory (default: /usr/local/bin).
  XDG_CONFIG_HOME  Configuration base, when absolute; otherwise HOME/.config.

Credentials, custom --config paths, the repository, and build artifacts are
never removed. The install directory is not removed.
EOF
}

confirm() {
    local prompt="$1"
    local answer=""
    [[ -t 0 && -t 1 ]] || die "Interactive confirmation requires a terminal."
    printf '%s' "$prompt"
    IFS= read -r answer || answer=""
    case "$answer" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

validate_target() {
    local target="$1"
    local kind="$2"

    [[ "$target" == /* && "$target" != "/" ]] ||
        die "Refusing unsafe removal path: $target"
    [[ ! -L "$target" ]] ||
        die "Refusing to remove a symbolic link: $target"
    if [[ -e "$target" ]]; then
        if [[ "$kind" == "file" && ! -f "$target" ]]; then
            die "Refusing to remove a non-regular executable target: $target"
        fi
        if [[ "$kind" == "directory" && ! -d "$target" ]]; then
            die "Refusing to remove a non-directory configuration target: $target"
        fi
    fi
}

remove_target() {
    local target="$1"
    local kind="$2"
    local parent

    validate_target "$target" "$kind"
    if [[ ! -e "$target" && ! -L "$target" ]]; then
        warn "Not present; skipping: $target"
        return 0
    fi

    parent="$(dirname -- "$target")"
    if [[ -w "$parent" && -x "$parent" ]]; then
        if [[ "$kind" == "file" ]]; then rm -f -- "$target"; else rm -r -- "$target"; fi
    else
        command -v sudo >/dev/null 2>&1 || die "sudo is required to remove: $target"
        if [[ "$kind" == "file" ]]; then sudo rm -f -- "$target"; else sudo rm -r -- "$target"; fi
    fi
    [[ ! -e "$target" && ! -L "$target" ]] ||
        die "Removal verification failed: $target"
    success "Removed: $target"
}

main() {
    local mode="binary"
    local mode_seen=0
    local dry_run=0
    local arg
    local -a targets=()

    for arg in "$@"; do
        case "$arg" in
            binary|all)
                [[ "$mode_seen" -eq 0 ]] || die "Specify only one mode."
                mode="$arg"
                mode_seen=1
                ;;
            --dry-run)
                [[ "$dry_run" -eq 0 ]] || die "Specify --dry-run once."
                dry_run=1
                ;;
            help|-h|--help) usage; return 0 ;;
            *) die "Unknown option or mode: $arg" ;;
        esac
    done

    [[ "$dry_run" -eq 1 || "$EUID" -ne 0 ]] ||
        die "Do not run this script as root. Run it normally."
    [[ "$INSTALL_DIR" != "/" ]] || die "Refusing unsafe installation directory: /"
    [[ ! -e "$INSTALL_DIR" || -d "$INSTALL_DIR" ]] ||
        die "Installation path is not a directory: $INSTALL_DIR"
    command -v rm >/dev/null 2>&1 || die "Required command not found: rm."
    command -v dirname >/dev/null 2>&1 || die "Required command not found: dirname."

    printf '\n%sRUXMSG removal utility%s\n' "$CYAN" "$RESET"
    info "Removal mode: $mode"
    printf '  Executable: %s\n' "$DESTINATION"
    validate_target "$DESTINATION" file
    targets+=("$DESTINATION")

    if [[ "$mode" == all ]]; then
        if [[ "${XDG_CONFIG_HOME:-}" == /* ]]; then
            config_base="$(normalize_path "$XDG_CONFIG_HOME")" ||
                die "XDG_CONFIG_HOME is not a valid absolute path."
        else
            [[ "${HOME:-}" == /* ]] ||
                die "HOME must be set to an absolute path to resolve the config directory."
            config_home="$(normalize_path "$HOME")" ||
                die "HOME is not a valid absolute path."
            config_base="$(normalize_path "${config_home}/.config")" ||
                die "Could not resolve the default config base directory."
        fi
        # Keep the application-specific leaf lexical so validate_target can
        # detect and refuse a symlink placed exactly at .../ruxmsg.
        config_dir="${config_base%/}/ruxmsg"
        if [[ "${HOME:-}" == /* ]]; then
            home_dir="$(normalize_path "$HOME")" || die "HOME is not a valid absolute path."
            case "$config_dir" in
                "$home_dir"|"$home_dir/.config"|"$home_dir/.local"|"$home_dir/.ssh")
                    die "Refusing unsafe configuration directory: $config_dir"
                    ;;
            esac
        fi
        case "$config_dir" in
            /|/usr|/usr/local|/etc|/var|/opt)
                die "Refusing unsafe configuration directory: $config_dir"
                ;;
        esac
        validate_target "$config_dir" directory
        targets+=("$config_dir")
        printf '\n%sFULL REMOVAL TARGETS%s\n' "$YELLOW" "$RESET"
        printf '  - %s\n' "${targets[@]}"
        warn "The configuration directory may contain user settings."
        warn "OS credential-store identities and custom config paths are retained."
        CONFIG_DIR="$config_dir"
    fi

    if [[ "$dry_run" -eq 1 ]]; then
        info "Dry run: no files were changed"
        return 0
    fi

    if [[ "$mode" == all ]]; then
        confirm "Permanently remove the listed targets? [y/N] " || {
            info "Removal cancelled."
            return 0
        }
    else
        printf '\nConfiguration, credentials, repository, and build artifacts will remain.\n\n'
        confirm "Uninstall ${APP_NAME}? [y/N] " || {
            info "Removal cancelled."
            return 0
        }
    fi

    info "Removing installed executable"
    remove_target "$DESTINATION" file
    if [[ "$mode" == all ]]; then
        info "Removing default configuration directory"
        remove_target "$CONFIG_DIR" directory
    fi
    printf '\n'
    success "${APP_NAME} filesystem removal completed."
    warn "This script does not erase identity credentials from the OS credential store."
}

main "$@"
