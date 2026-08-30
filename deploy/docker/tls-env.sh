# Write PEM files from Secrets Manager env vars. Sourced by container entrypoints.
# No-op when SEG_TLS_CERT / SEG_TLS_KEY are unset (local compose / pytest).

segs_write_tls() {
  _dir="${SEG_TLS_DIR:-/opt/segs/tls}"
  if [ -z "${SEG_TLS_CERT:-}" ] || [ -z "${SEG_TLS_KEY:-}" ]; then
    return 0
  fi
  mkdir -p "$_dir"
  umask 077
  printf '%s' "$SEG_TLS_CERT" > "$_dir/server.crt"
  printf '%s' "$SEG_TLS_KEY" > "$_dir/server.key"
  chmod 600 "$_dir/server.crt" "$_dir/server.key"
  if [ -n "${SEG_TLS_CA:-}" ]; then
    printf '%s' "$SEG_TLS_CA" > "$_dir/ca.crt"
    chmod 644 "$_dir/ca.crt"
    export SEG_TLS_CA_PATH="$_dir/ca.crt"
  fi
  export SEG_TLS_CERT_PATH="$_dir/server.crt"
  export SEG_TLS_KEY_PATH="$_dir/server.key"
}
