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

# ── SSH (contract §18.7, spike S4/S4b–S4f) ──────────────────────────────
# People's SSH certificates: one role per host group, ssh_user/roles/hg-<id>,
# written only by enroll from the Hub's compilation. Every role field is a
# string (JSON booleans are refused by allowed_parameters). ttl / max_ttl
# are pinned to the twelve whole-hour values up to 12 h: a role's max_ttl
# above the mount's max-lease-ttl would sign past it (S4c), so this list is
# the 12 h limit. Even with this policy enroll can't make a role that
# issues host certificates, X11 / user-rc / force-command certificates or
# certificates over 12 h.
#
# What a stolen enroll token can still do on a role (security review,
# checked live on Vault 2.2.1 by TestLiveSSHVault):
#   - allowed_users: only "s:…" / "u:…" lists (so never "*", whose bare
#     value Vault reads as "any principal"); Vault matches every entry
#     exactly (no glob, an embedded "*" entry isn't a wildcard, live), and
#     allowed_users_template can't be set. The list's contents (which
#     principals) can't be pinned here: enroll checks the grammar and the
#     host group of each, and the Hub compares the read-back.
#   - default_extensions: only {} (Vault applies a role's defaults without
#     checking allowed_extensions, so a default could add X11 / user-rc;
#     enroll sends the extensions map on every sign instead).
#   - default_critical_options: not pinnable (the per-host-group
#     source-address). The only OpenSSH critical options (force-command,
#     source-address, verify-required) restrict a certificate, so the worst
#     a stolen token does here is drop source-address — which writing the
#     role with allowed_critical_options "" does as well.
#   - allowed_user_key_lengths: not pinnable (Vault compares the policy's
#     numbers with the request's JSON numbers by type and never matches, live);
#     enroll accepts only the four key types itself.
path "ssh_user/sign/hg-*" {
  capabilities = ["update"]
  # source-address comes from the role only; never a host certificate.
  denied_parameters = {
    "cert_type"        = []
    "critical_options" = []
  }
}

path "ssh_user/roles/hg-*" {
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = {
    "key_type"                 = ["ca"]
    "allow_user_certificates"  = ["true"]
    "allow_host_certificates"  = ["false"]
    "allow_user_key_ids"       = ["true"]
    "allowed_users"            = ["s:*", "u:*"]
    "allowed_extensions"       = ["permit-pty", "permit-pty,permit-port-forwarding",
                                  "permit-pty,permit-agent-forwarding",
                                  "permit-pty,permit-port-forwarding,permit-agent-forwarding"]
    "default_extensions"       = [{}]
    "allowed_critical_options" = ["", "source-address"]
    "default_critical_options" = []
    "allowed_user_key_lengths" = []
    "ttl"                      = ["3600", "7200", "10800", "14400", "18000", "21600",
                                  "25200", "28800", "32400", "36000", "39600", "43200"]
    "max_ttl"                  = ["3600", "7200", "10800", "14400", "18000", "21600",
                                  "25200", "28800", "32400", "36000", "39600", "43200"]
  }
}

# Stale hg-* roles (the Hub deletes roles without grants).
path "ssh_user/roles/" {
  capabilities = ["list"]
}

# Host certificates: exactly cert_type=host (the default, user, is refused
# by the host role), plus key_id and the documented fields.
path "ssh_host/sign/host" {
  capabilities = ["update"]
  allowed_parameters = {
    "cert_type" = ["host"]
    "*"         = []
  }
}

# GET /internal/ssh-ca: the CA public keys and the §18.7 checks (no sudo
# needed for the tunes, S4d).
path "ssh_user/config/ca" {
  capabilities = ["read"]
}

path "ssh_host/config/ca" {
  capabilities = ["read"]
}

path "sys/mounts/ssh_user/tune" {
  capabilities = ["read"]
}

path "sys/mounts/ssh_host/tune" {
  capabilities = ["read"]
}

path "ssh_host/roles/host" {
  capabilities = ["read"]
}
