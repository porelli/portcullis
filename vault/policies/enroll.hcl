# Least-privilege policy for enroll (enroll/main.go).
# Attached to the `portcullis-enroll` AppRole by ./portcullis vault init.
#
# enroll works on both CAs of the internal certificate authority: pki_int
# (YubiKey certificates) and pki_file (browser certificates). It needs
# exactly (contract §8.1 "Internal certificate authority", §9.4):
#   - sign a YubiKey certificate's CSR with the client-cert role
#     (POST /internal/yubikey-certificates[/renew])
#   - sign a browser certificate's CSR with the browser-cert role
#     (POST /internal/browser-certificates; enroll makes the key itself)
#   - list issued serials and read certificates on both mounts
#     (GET /internal/certificates, the renew / limit / revoke lookups)
#   - revoke on both mounts and rotate that mount's CRL
#     (POST /internal/certificates/revoke)
# Signing never takes SANs: the certificate names exactly the username
# enroll passes as common_name. denied_parameters with [] refuses the
# parameter with any value (the roles also have allow_ip_sans=false and no
# allowed URI / other SANs).
# Token self-lookup/renew comes from Vault's built-in `default` policy.

path "pki_int/sign/client-cert" {
  capabilities = ["update"]
  denied_parameters = {
    "alt_names"  = []
    "ip_sans"    = []
    "uri_sans"   = []
    "other_sans" = []
  }
}

path "pki_file/sign/browser-cert" {
  capabilities = ["update"]
  denied_parameters = {
    "alt_names"  = []
    "ip_sans"    = []
    "uri_sans"   = []
    "other_sans" = []
  }
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_file/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_file/cert/*" {
  capabilities = ["read"]
}

path "pki_int/revoke" {
  capabilities = ["update"]
}

path "pki_file/revoke" {
  capabilities = ["update"]
}

path "pki_int/crl/rotate" {
  capabilities = ["read"]
}

path "pki_file/crl/rotate" {
  capabilities = ["read"]
}
