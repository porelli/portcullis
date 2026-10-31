# Least-privilege policy for the enrollment UI (enroll/main.go).
# Attached to the `portcullis-enroll` AppRole by scripts/vault-init.sh.
#
# enroll needs exactly three things:
#   - sign a user's CSR with the client-cert role  (POST /api/sign)
#   - list issued certificate serials              (GET /certs)
#   - read individual certificates                 (GET /certs)
# Token self-lookup/renew comes from Vault's built-in `default` policy.

path "pki_int/sign/client-cert" {
  capabilities = ["update"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}
