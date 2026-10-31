# Portcullis Vault server configuration (mounted read-only into the vault
# container at /vault/portcullis/vault.hcl, see docker-compose.yml).
#
# - Integrated (raft) storage on the `vault_data` volume, so the PKI
#   (root + intermediate CA keys, issued-cert records, CRL) survives
#   restarts.
# - Plain HTTP listener: Vault is only reachable on the internal
#   `portcullis` Docker network and on 127.0.0.1:8200 on the host.
#   Never publish 8200 on a non-loopback address without enabling TLS.
# - disable_mlock = true is HashiCorp's recommendation for integrated
#   storage (mlock + the memory-mapped raft DB can trigger OOM kills), so
#   the container no longer needs CAP_IPC_LOCK. Make sure the host has
#   swap disabled or encrypted if that matters to you.
#
# Initialisation and unsealing are automated by ./portcullis vault init and
# vault/entrypoint.sh (see docs/certificates.md "Vault storage & unsealing").

ui            = true
disable_mlock = true

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"

# /vault/file exists in the image, owned by the `vault` user. The image runs
# Vault as that non-root user, so a fresh named volume mounted here inherits
# the right ownership (Docker copies it from the image directory); a new
# mountpoint like /vault/data would be root-owned and raft could not write.
storage "raft" {
  path    = "/vault/file"
  node_id = "portcullis-vault-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}
