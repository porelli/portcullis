#!/usr/bin/env python3
"""Mail provider conformance (contract §19.5; mail provider plan P11).

    run.py --level api|full --api-url URL --secret-file FILE
           [--outside-url URL] [--smtp-host H --imap-host H] [--ca-file PEM]
           [--spki HEX]

One line per check ("PASS <name>" / "FAIL <name>: <why>"); exit 1 on any
failure, 2 on a usage error. `api` judges the provider API alone (any
provider, mail-fake included); `full` adds the mail protocol checks
(a provider with a mail server: stalwart). The checks write documents
and passwords: run them only against a provider set aside for it, the
Hub stopped (CI). The secret is read from its file, never an argument.
"""
import argparse
import ssl
import sys

import checks_api
import checks_proto


def main(argv=None, opener=None, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="run.py")
    ap.add_argument("--level", choices=["api", "full"], required=True)
    ap.add_argument("--api-url", required=True)
    ap.add_argument("--secret-file", required=True)
    ap.add_argument("--outside-url")
    ap.add_argument("--smtp-host")
    ap.add_argument("--imap-host")
    ap.add_argument("--ca-file")
    ap.add_argument("--spki", help="the sha256 of the key the provider serves (hex); documents carry it")
    a = ap.parse_args(argv)
    if a.spki is not None and not (len(a.spki) == 64 and all(c in "0123456789abcdef" for c in a.spki)):
        ap.error("--spki must be 64 lowercase hex characters")
    if a.level == "full" and not (a.smtp_host and a.imap_host):
        ap.error("--level full needs --smtp-host and --imap-host")
    try:
        with open(a.secret_file) as f:
            secret = f.read().strip()
    except OSError as e:
        print("FAIL setup: the secret file: %s" % e.strerror, file=out)
        return 1
    if len(secret) < 32:
        print("FAIL setup: the secret file holds fewer than 32 characters", file=out)
        return 1
    if a.ca_file:
        checks_proto.CTX = ssl.create_default_context(cafile=a.ca_file)
        checks_proto.CTX.check_hostname = False  # the mail host name isn't the address dialled
    ctx = checks_api.Ctx(a.api_url, secret, a.outside_url, opener)
    ctx.smtp_host, ctx.imap_host = a.smtp_host, a.imap_host
    if a.spki:
        ctx.spki = a.spki
    checks = list(checks_api.API_CHECKS)
    if a.level == "full":
        # The protocol checks before the void (the last API check).
        checks = checks[:-1] + checks_proto.PROTO_CHECKS + checks[-1:]
    failed = 0
    for name, fn in checks:
        try:
            why = fn(ctx)
        except Exception as e:  # a check that crashes fails, never stops the run
            why = "%s: %s" % (type(e).__name__, e)
        if why:
            failed += 1
            print("FAIL %s: %s" % (name, why), file=out)
        else:
            print("PASS %s" % name, file=out)
    print("%d checks, %d failed" % (len(checks), failed), file=out)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
