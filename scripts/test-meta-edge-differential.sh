#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run this live TLS differential as root (it binds 127.0.0.1:443)" >&2
    exit 77
fi

: "${D2O_TELEGRAM_BIN:?set D2O_TELEGRAM_BIN to the pinned production d2ktg binary}"
: "${R2O_TELEGRAM_BIN:?set R2O_TELEGRAM_BIN to the production r2o-telegram binary}"
for command in openssl python3 timeout; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing required command: $command" >&2
        exit 77
    }
done

tmpdir=$(mktemp -d)
server_pid=
cleanup() {
    if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM

make_ca() {
    name=$1
    subject=$2
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.pem" \
        -sha256 -days 1 -subj "/CN=$subject" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}

issue_leaf() {
    name=$1
    hostname=$2
    ca_name=$3
    openssl req -new -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" \
        -sha256 -subj "/CN=$hostname" >/dev/null 2>&1
    cat >"$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$hostname
EOF
    openssl x509 -req -in "$name.csr" -CA "$ca_name.pem" -CAkey "$ca_name.key" \
        -CAcreateserial -out "$name.pem" -days 1 -sha256 -extfile "$name.ext" \
        >/dev/null 2>&1
}

start_tls_peer() {
    cert=$1
    key=$2
    sni_log=$3
    peer_log=$4
    python3 - "$cert" "$key" "$sni_log" >"$peer_log" 2>&1 <<'PY' &
import socket
import ssl
import sys

cert_path, key_path, sni_path = sys.argv[1:]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_path, key_path)

def record_sni(_socket, server_name, _context):
    with open(sni_path, "a", encoding="ascii") as output:
        output.write((server_name or "<none>") + "\n")

context.set_servername_callback(record_sni)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 443))
listener.listen(4)
listener.settimeout(15)
print("ready", flush=True)
for _ in range(2):
    connection, _address = listener.accept()
    try:
        with context.wrap_socket(connection, server_side=True):
            pass
    except (OSError, ssl.SSLError):
        connection.close()
listener.close()
PY
    server_pid=$!
}

wait_tls_peer() {
    attempts=0
    while [ "$attempts" -lt 50 ]; do
        if grep -Fqx "ready" "$1"; then
            return 0
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then
            cat "$1" >&2
            return 1
        fi
        sleep 0.1
        attempts=$((attempts + 1))
    done
    cat "$1" >&2
    echo "TLS fixture did not become ready" >&2
    return 1
}

run_client() {
    client_label=$1
    client_binary=$2
    client_host=$3
    client_ca_bundle=$4
    expected_status=$5
    client_output=$tmpdir/$client_label.log
    set +e
    timeout 8 "$client_binary" --check-instagram-ip "$client_host" 127.0.0.1 "$client_ca_bundle" >"$client_output" 2>&1
    status=$?
    set -e
    if [ "$status" -ne "$expected_status" ]; then
        cat "$client_output" >&2
        echo "$client_label returned $status; expected $expected_status" >&2
        return 1
    fi
    printf '%s exit=%s\n' "$client_label" "$status"
}

run_case() {
    label=$1
    cert=$2
    key=$3
    ca_bundle=$4
    host=$5
    expected=$6
    sni_log=$tmpdir/$label.sni
    peer_log=$tmpdir/$label.peer
    : >"$sni_log"
    start_tls_peer "$cert" "$key" "$sni_log" "$peer_log"
    wait_tls_peer "$peer_log"
    run_client "$label-d2o" "$D2O_TELEGRAM_BIN" "$host" "$ca_bundle" "$expected"
    run_client "$label-r2o" "$R2O_TELEGRAM_BIN" "$host" "$ca_bundle" "$expected"
    if ! wait "$server_pid"; then
        cat "$peer_log" >&2
        echo "$label TLS peer did not serve both clients" >&2
        return 1
    fi
    server_pid=
    sni_count=$(wc -l <"$sni_log" | tr -d '[:space:]')
    if [ "$sni_count" -ne 2 ] || grep -Fvxq "example.com" "$sni_log"; then
        cat "$sni_log" >&2
        echo "$label C/Rust clients did not both use neutral SNI example.com" >&2
        return 1
    fi
    printf '%s neutral_sni_count=%s\n' "$label" "$sni_count"
}

mkdir -p "$tmpdir/certs"
make_ca "$tmpdir/certs/trusted" "R2O test trusted CA"
make_ca "$tmpdir/certs/untrusted" "R2O test untrusted CA"
issue_leaf "$tmpdir/certs/instagram" "instagram.com" "$tmpdir/certs/trusted"
issue_leaf "$tmpdir/certs/example" "example.com" "$tmpdir/certs/trusted"
issue_leaf "$tmpdir/certs/untrusted-instagram" "instagram.com" "$tmpdir/certs/untrusted"

run_case valid-instagram "$tmpdir/certs/instagram.pem" "$tmpdir/certs/instagram.key" \
    "$tmpdir/certs/trusted.pem" "instagram.com" 0
run_case canonical-alias "$tmpdir/certs/instagram.pem" "$tmpdir/certs/instagram.key" \
    "$tmpdir/certs/trusted.pem" "instagram.c10r.instagram.com" 0
run_case wrong-certificate-name "$tmpdir/certs/example.pem" "$tmpdir/certs/example.key" \
    "$tmpdir/certs/trusted.pem" "instagram.com" 1
run_case untrusted-certificate "$tmpdir/certs/untrusted-instagram.pem" \
    "$tmpdir/certs/untrusted-instagram.key" "$tmpdir/certs/trusted.pem" \
    "instagram.com" 1

for binary_name in d2o r2o; do
    if [ "$binary_name" = d2o ]; then
        binary=$D2O_TELEGRAM_BIN
    else
        binary=$R2O_TELEGRAM_BIN
    fi
    set +e
    timeout 8 "$binary" --check-instagram-ip "example.com" 127.0.0.1 \
        "$tmpdir/certs/trusted.pem" >"$tmpdir/$binary_name-invalid.log" 2>&1
    status=$?
    set -e
    if [ "$status" -ne 2 ]; then
        cat "$tmpdir/$binary_name-invalid.log" >&2
        echo "$binary_name accepted an unsupported Meta hostname (exit $status)" >&2
        exit 1
    fi
    printf '%s-unsupported-host exit=%s\n' "$binary_name" "$status"
done

echo "production_meta_edge_tls_differential=passed"
