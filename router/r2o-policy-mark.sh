#!/bin/sh
# Извлечение метки политики Keenetic из `ndmc show ip policy`.
# D2K files/S99d2k:policy_mark: ID приоритетнее уникального описания.

r2o_keenetic_policy_mark() {
    policy=$1
    command -v ndmc >/dev/null 2>&1 || return 0
    policy_list=$(ndmc -c "show ip policy" 2>/dev/null) || return 0
    printf '%s\n' "$policy_list" | tr -d '\033' | awk -v want="$policy" '
        /policy, name = / {
            line = $0; sub(/.*policy, name = /, "", line)
            name = line; sub(/,.*/, "", name)
            sub(/:[[:space:]]*$/, "", name); sub(/[[:space:]]+$/, "", name)
            desc = ""
            if (line ~ /description = /) {
                desc = line; sub(/.*description = /, "", desc)
                sub(/:[[:space:]]*$/, "", desc); sub(/[[:space:]]+$/, "", desc)
            }
            exact = (name == want)
            bydesc = (desc == want)
            next
        }
        /^[[:space:]]*mark:/ {
            if (exact) { id_count++; id_mark=$2 }
            if (bydesc) { desc_count++; desc_mark=$2 }
            exact=0; bydesc=0
        }
        END {
            if (id_count == 1) print id_mark
            else if (id_count == 0 && desc_count == 1) print desc_mark
        }'
}
