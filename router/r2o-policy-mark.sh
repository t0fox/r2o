#!/bin/sh
# Извлечение метки политики Keenetic из `ndmc show ip policy`.
# Точная копия логики D2O `files/S99d2k:policy_mark`.

r2o_keenetic_policy_mark() {
    policy=$1
    command -v ndmc >/dev/null 2>&1 || return 0
    ndmc -c "show ip policy" 2>/dev/null | tr -d '\033' | awk -v want="$policy" '
        /policy, name = / {
            line = $0; sub(/.*policy, name = /, "", line)
            name = line; sub(/,.*/, "", name)
            sub(/:[[:space:]]*$/, "", name); sub(/[[:space:]]+$/, "", name)
            desc = ""
            if (line ~ /description = /) {
                desc = line; sub(/.*description = /, "", desc)
                sub(/:[[:space:]]*$/, "", desc); sub(/[[:space:]]+$/, "", desc)
            }
            cur = (name == want || desc == want)
            next
        }
        cur && /^[[:space:]]*mark:/ { print $2; exit }'
}
