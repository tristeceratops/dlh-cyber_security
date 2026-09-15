#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DEST="tool_evaluation"
MANIFEST="${DEST}/MANIFEST.json"
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "$TMP_MANIFEST"' EXIT

mkdir -p \
    "$DEST/findings" \
    "$DEST/rules/wazuh" \
    "$DEST/comparison/questions" \
    "$DEST/comparison" \
    "$DEST/playbook" \
    "$DEST/brief" \
    "$DEST/workspace" \
    "$DEST/runtime"

copy_folder_contents() {
    local source="$1"
    local target="$2"
    local label="$3"

    mkdir -p "$target"

    if [[ ! -d "$source" ]]; then
        printf 'warning: %-13s source folder missing: %s\n' "$label" "$source"
        return 0
    fi

    if [[ -z "$(find "$source" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        printf 'warning: %-13s source folder is empty: %s\n' "$label" "$source"
        return 0
    fi

    printf 'copying %-13s contents from %s\n' "$label" "$source"

    find "$source" -mindepth 1 -maxdepth 1 -type f -print0 |
        while IFS= read -r -d '' file; do
            cp -f -- "$file" "$target/"
        done
}

copy_runtime_scripts() {
    local target="$DEST/runtime"
    local copied=0

    printf 'copying %-13s task scripts from current directory\n' "runtime"

    while IFS= read -r -d '' file; do
        local name
        name="$(basename "$file")"

        if [[ "$name" =~ ^([0-9]|1[0-3])[-_].*\.sh$ ]]; then
            cp -f -- "$file" "$target/"
            copied=$((copied + 1))
        fi
    done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -print0)

    if (( copied == 0 )); then
        printf 'warning: runtime       no task scripts 0-13 found\n'
    fi
}

copy_folder_contents "$SCRIPT_DIR/findings" \
    "$DEST/findings" \
    "findings"

copy_folder_contents "$SCRIPT_DIR/rules/wazuh" \
    "$DEST/rules/wazuh" \
    "rules"

copy_folder_contents "$SCRIPT_DIR/comparison/questions" \
    "$DEST/comparison/questions" \
    "questions"

copy_folder_contents "$SCRIPT_DIR/comparison" \
    "$DEST/comparison" \
    "comparison"

copy_folder_contents "$SCRIPT_DIR/playbook" \
    "$DEST/playbook" \
    "playbook"

copy_folder_contents "$SCRIPT_DIR/brief" \
    "$DEST/brief" \
    "brief"

copy_folder_contents "$SCRIPT_DIR/workspace" \
    "$DEST/workspace" \
    "workspace"

copy_runtime_scripts

printf 'generating     MANIFEST.json\n'

{
    printf '[\n'

    first=1

    while IFS= read -r -d '' file; do
        relative="${file#"$DEST"/}"
        size="$(stat -c '%s' "$file")"
        sha256="$(sha256sum "$file" | awk '{print $1}')"

        if (( first == 0 )); then
            printf ',\n'
        fi
        first=0

        jq -n \
            --arg path "$relative" \
            --argjson size "$size" \
            --arg sha256 "$sha256" \
            '{path: $path, size: $size, sha256: $sha256}'
    done < <(
        find "$DEST" \
            -type f \
            ! -path "$MANIFEST" \
            -print0 |
        sort -z
    )

    printf '\n]\n'
} > "$TMP_MANIFEST"

mv -f "$TMP_MANIFEST" "$MANIFEST"

printf 'sanity check   : '

missing=0
empty=0

while IFS= read -r -d '' file; do
    if [[ ! -e "$file" ]]; then
        printf '\nmissing: %s\n' "$file"
        missing=$((missing + 1))
    elif [[ ! -s "$file" ]]; then
        printf '\nempty: %s\n' "$file"
        empty=$((empty + 1))
    fi
done < <(
    find "$DEST" \
        -type f \
        ! -name 'MANIFEST.json' \
        -print0
)

if (( missing > 0 || empty > 0 )); then
    printf 'completed with warnings\n'
    printf 'missing files: %d\n' "$missing"
    printf 'empty files:   %d\n' "$empty"
else
    printf 'ok\n'
fi

entries="$(jq 'length' "$MANIFEST")"

printf 'MANIFEST.json  : %s entries\n' "$entries"
printf '%s/ ready\n' "$DEST"
