#!/bin/bash
# 把 ocproxy + 其非系统 dylib 依赖打包进 XDVPN.app/Contents/Resources/openconnect/
# （和 openconnect 共用 bin/ 和 lib/ 目录）
#
# 用法： vendor-ocproxy.sh <path-to-app>
# 前置： 先跑 vendor-openconnect.sh —— 需要 lib/ 目录已存在
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:?usage: vendor-ocproxy.sh build/XDVPN.app}"
BIN_DIR="$APP/Contents/Resources/openconnect/bin"
LIB_DIR="$APP/Contents/Resources/openconnect/lib"

if [[ ! -d "$BIN_DIR" ]]; then
    echo "error: $BIN_DIR not found; run vendor-openconnect.sh first" >&2
    exit 1
fi

find_ocproxy() {
    if [[ -n "${XDVPN_OCPROXY_PATH:-}" && -x "${XDVPN_OCPROXY_PATH:-}" ]]; then
        printf '%s\n' "$XDVPN_OCPROXY_PATH"
        return
    fi
    for path in /opt/homebrew/bin/ocproxy /usr/local/bin/ocproxy; do
        if [[ -x "$path" ]]; then
            printf '%s\n' "$path"
            return
        fi
    done
    if command -v ocproxy >/dev/null 2>&1; then
        command -v ocproxy
        return
    fi
    return 1
}

source_bin="$(find_ocproxy || true)"
if [[ -z "$source_bin" ]]; then
    echo "error: ocproxy 未找到；先 brew install ocproxy" >&2
    exit 1
fi
source_bin="$(realpath "$source_bin")"

brew_prefixes=("/opt/homebrew" "/usr/local")

is_system_dep() {
    case "$1" in
      /usr/lib/*|/System/Library/*) return 0 ;;
      *) return 1 ;;
    esac
}

resolve_dep() {
    local dep="$1"
    case "$dep" in
      /*)
        [[ -f "$dep" ]] && realpath "$dep"
        ;;
      @rpath/*|@loader_path/*|@executable_path/*)
        local base="$(basename "$dep")"
        for prefix in "${brew_prefixes[@]}"; do
            for candidate in "$prefix/lib/$base" "$prefix"/opt/*/lib/"$base" "$prefix"/Cellar/*/*/lib/"$base"; do
                if [[ -f "$candidate" ]]; then
                    realpath "$candidate"
                    return
                fi
            done
        done
        ;;
    esac
}

deps_for() { otool -L "$1" | tail -n +2 | awk '{print $1}'; }

QUEUE_FILE="$(mktemp)"
SEEN_FILE="$(mktemp)"
trap 'rm -f "$QUEUE_FILE" "$SEEN_FILE"' EXIT

enqueue_library() {
    local real="$(realpath "$1")"
    grep -Fxq "$real" "$SEEN_FILE" && return
    echo "$real" >> "$SEEN_FILE"
    echo "$real" >> "$QUEUE_FILE"
}

# 1) Copy the binary
cp -L "$source_bin" "$BIN_DIR/ocproxy"
chmod 0755 "$BIN_DIR/ocproxy"

# 2) Enumerate ocproxy's deps
while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    is_system_dep "$dep" && continue
    resolved="$(resolve_dep "$dep" || true)"
    if [[ -z "$resolved" ]]; then
        echo "error: 无法解析 $dep （来自 $source_bin）" >&2
        exit 1
    fi
    enqueue_library "$resolved"
done < <(deps_for "$source_bin")

# 3) BFS: copy any not-yet-vendored libs and walk their deps
while [[ -s "$QUEUE_FILE" ]]; do
    dep="$(head -n 1 "$QUEUE_FILE")"
    tail -n +2 "$QUEUE_FILE" > "$QUEUE_FILE.tmp"
    mv "$QUEUE_FILE.tmp" "$QUEUE_FILE"

    dst="$LIB_DIR/$(basename "$dep")"
    if [[ ! -f "$dst" ]]; then
        cp -L "$dep" "$dst"
        chmod u+rw,go+r "$dst"
    fi
    while IFS= read -r child; do
        [[ -z "$child" ]] && continue
        is_system_dep "$child" && continue
        resolved="$(resolve_dep "$child" || true)"
        if [[ -z "$resolved" ]]; then
            echo "error: 无法解析 $child （来自 $dep）" >&2
            exit 1
        fi
        enqueue_library "$resolved"
    done < <(deps_for "$dep")
done

# 4) Rewrite ocproxy's own load commands → @loader_path/../lib/<base>
while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    is_system_dep "$dep" && continue
    base="$(basename "$dep")"
    install_name_tool -change "$dep" "@loader_path/../lib/$base" "$BIN_DIR/ocproxy" 2>/dev/null || true
done < <(deps_for "$BIN_DIR/ocproxy")

# 5) Rewrite any newly-added libs' deps + their install IDs
for lib in "$LIB_DIR"/*.dylib; do
    [[ -e "$lib" ]] || continue
    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        is_system_dep "$dep" && continue
        base="$(basename "$dep")"
        install_name_tool -change "$dep" "@loader_path/$base" "$lib" 2>/dev/null || true
    done < <(deps_for "$lib")
    install_name_tool -id "@loader_path/$(basename "$lib")" "$lib" 2>/dev/null || true
done

echo "==> vendored ocproxy from $source_bin"
