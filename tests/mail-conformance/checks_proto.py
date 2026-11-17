"""The full level's mail protocol checks (P11): a provider with a real
mail server behind its listeners. Every message stays local: foreign
recipients are only tried at RCPT (refused), nothing is ever sent out.
"""
import imaplib
import smtplib
import ssl

from checks_api import UUIDS, cred, doc, put

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # the mail certificate is a CI one


def _rcpt(host, port, rcpt):
    s = smtplib.SMTP(host, port, timeout=20)
    try:
        s.ehlo("conformance.example")
        s.mail("probe@conformance.example")
        return s.rcpt(rcpt), s.esmtp_features
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass


def check_no_open_relay(ctx):
    (c, m), _ = _rcpt(ctx.smtp_host, 25, "x@foreign.test")
    if not 500 <= c < 600:
        return "a foreign recipient on 25: %d %r (want 5xx)" % (c, m[:80])
    return None


def check_no_auth_on_25(ctx):
    _, feats = _rcpt(ctx.smtp_host, 25, "postmaster@conformance.test")
    if "auth" in feats:
        return "AUTH offered on port 25"
    return None


def _alice(ctx, lan_only=False, local=None):
    st, _, b = put(ctx, doc(ctx, ["alice", "bob"], lan_only=lan_only, local=local))
    if st != 202:
        return None, "PUT a document: HTTP %d %s" % (st, b[:200])
    st, j = cred(ctx, "alice", UUIDS[0], "proto")
    if st != 201:
        return None, "create a password: HTTP %d" % st
    return j["secret"], None


def check_foreign_from(ctx):
    pw, err = _alice(ctx)
    if err:
        return err
    s = smtplib.SMTP(ctx.smtp_host, 587, timeout=20)
    try:
        s.starttls(context=CTX)
        s.login("alice@conformance.test", pw)
        s.mail("alice@conformance.test")
        s.rcpt("alice@conformance.test")
        c, m = s.data(b"From: boss@foreign.test\r\nTo: alice@conformance.test\r\nSubject: c\r\n\r\nc\r\n")
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
    if c < 500:
        return "a foreign From: was accepted on submission: %d" % c
    return None


def check_mail_password_not_api(ctx):
    pw, err = _alice(ctx)
    if err:
        return err
    st, _, _ = ctx.call("GET", "/v1/provider", bearer=pw)
    if st != 403:
        return "a mail password on the API: HTTP %d (want 403)" % st
    return None


def check_parking(ctx):
    put(ctx, doc(ctx, ["alice", "bob"]))
    st, _, _ = put(ctx, doc(ctx, ["alice"]))
    if st != 202:
        return "removing bob: HTTP %d" % st
    (c, m), _ = _rcpt(ctx.smtp_host, 25, "bob@conformance.test")
    if c != 550 or b"5.1.1" not in m:
        return "a parked address at RCPT: %d %r (want 550 5.1.1)" % (c, m[:80])
    return None


def check_lan_only_sasl(ctx):
    pw, err = _alice(ctx, lan_only=True, local=["192.0.2.0/24"])  # never the runner
    if err:
        return err
    s = smtplib.SMTP(ctx.smtp_host, 587, timeout=20)
    try:
        s.starttls(context=CTX)
        try:
            s.login("alice@conformance.test", pw)
        except smtplib.SMTPAuthenticationError:
            return None
        return "LAN-only: a login from outside the local networks was accepted"
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
        put(ctx, doc(ctx, ["alice"]))


def check_imap_login(ctx):
    pw, err = _alice(ctx)
    if err:
        return err
    i = imaplib.IMAP4_SSL(ctx.imap_host, 993, ssl_context=CTX)
    try:
        i.login("alice@conformance.test", pw)
    except imaplib.IMAP4.error as e:
        return "IMAP login with a new mail password: %s" % e
    finally:
        try:
            i.logout()
        except imaplib.IMAP4.error:
            pass
    return None


PROTO_CHECKS = [
    ("no_open_relay", check_no_open_relay),
    ("no_auth_on_25", check_no_auth_on_25),
    ("imap_login", check_imap_login),
    ("foreign_from_refused", check_foreign_from),
    ("mail_password_not_api", check_mail_password_not_api),
    ("parking_550_5_1_1", check_parking),
    ("lan_only_sasl_refused", check_lan_only_sasl),
]
