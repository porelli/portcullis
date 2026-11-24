"""The full level's mail protocol checks (P11): a provider with a real
mail server behind its listeners. Every message stays local: foreign
recipients are only tried at RCPT (refused), nothing is ever sent out.
"""
import imaplib
import smtplib
import ssl

from checks_api import SENDER_UUIDS, SENDERS, UUIDS, cred, doc, put

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
    # The earlier checks' passwords revoked first: a provider holds at
    # most 5 active ones per person (contract §19.5: error_kind limit).
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + UUIDS[0])
    for r in rows if st == 200 and isinstance(rows, list) else []:
        ctx.call("DELETE", "/v1/credentials/%s?uuid=%s" % (r.get("id"), UUIDS[0]))
    st, j = cred(ctx, "alice", UUIDS[0], "proto")
    if st != 201:
        return None, "create a password: HTTP %d %s" % (st, (j or {}).get("error_kind") or (j or {}).get("error") or "")
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
        except smtplib.SMTPNotSupportedError:
            # AUTH not offered outside the local networks: refused too.
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


def _sender(ctx):
    """A document with alice and one app sender, and the sender's
    credential (no allowed_ips: the runner submits from outside any app
    network)."""
    st, _, b = put(ctx, doc(ctx, ["alice", "bob"], senders=[0]))
    if st != 202:
        return None, "PUT a document with a sender: HTTP %d %s" % (st, b[:200])
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + SENDER_UUIDS[0])
    for r in rows if st == 200 and isinstance(rows, list) else []:
        ctx.call("DELETE", "/v1/credentials/%s?uuid=%s" % (r.get("id"), SENDER_UUIDS[0]))
    st, j = cred(ctx, SENDERS[0], SENDER_UUIDS[0], "proto")
    if st != 201:
        return None, "the sender's credential: HTTP %d %s" % (st, (j or {}).get("error_kind") or (j or {}).get("error") or "")
    return j["secret"], None


def _sender_data(ctx, pw, header_from):
    """(code at DATA, message): a submission as the sender to alice."""
    addr = SENDERS[0] + "@conformance.test"
    s = smtplib.SMTP(ctx.smtp_host, 587, timeout=20)
    try:
        s.starttls(context=CTX)
        s.login(addr, pw)
        s.mail(addr)
        c, m = s.rcpt("alice@conformance.test")
        if c >= 300:
            return c, m
        try:
            return s.data(("From: %s\r\nTo: alice@conformance.test\r\nSubject: sender\r\n\r\nconformance\r\n" % header_from).encode())
        except smtplib.SMTPDataError as e:
            return e.smtp_code, e.smtp_error
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass


def check_sender_submits_own_from(ctx):
    """An app sender submits with its own address (§19.14)."""
    pw, err = _sender(ctx)
    if err:
        return err
    c, m = _sender_data(ctx, pw, SENDERS[0] + "@conformance.test")
    if c != 250:
        return "the sender's own From: %d %r (want 250)" % (c, m[:80])
    return None


def check_sender_foreign_from(ctx):
    """Any other From: is refused at DATA (§19.14)."""
    pw, err = _sender(ctx)
    if err:
        return err
    for frm in ("alice@conformance.test", "boss@foreign.test"):
        c, m = _sender_data(ctx, pw, frm)
        if c < 500:
            return "the sender with From: %s: %d %r (want 5xx at DATA)" % (frm, c, m[:80])
    return None


def check_sender_inbound_refused(ctx):
    """Mail to a sender's address is refused at RCPT with 550 5.1.1."""
    _, err = _sender(ctx)
    if err:
        return err
    (c, m), _ = _rcpt(ctx.smtp_host, 25, SENDERS[0] + "@conformance.test")
    if c != 550 or b"5.1.1" not in m:
        return "a sender's address at RCPT: %d %r (want 550 5.1.1)" % (c, m[:80])
    return None


def check_sender_no_imap(ctx):
    """A sender's credential opens no mailbox: IMAP refuses it."""
    pw, err = _sender(ctx)
    if err:
        return err
    i = imaplib.IMAP4_SSL(ctx.imap_host, 993, ssl_context=CTX)
    try:
        i.login(SENDERS[0] + "@conformance.test", pw)
    except imaplib.IMAP4.error:
        return None
    finally:
        try:
            i.logout()
        except imaplib.IMAP4.error:
            pass
        put(ctx, doc(ctx, ["alice"], senders=[]))
    return "an IMAP login with a sender's credential was accepted"


def check_sender_rate_limit(ctx):
    """Each sender is rate-limited (§19.14): 10 messages a minute, 60 an
    hour. A fresh sender's first 10 messages in a row are accepted, the
    eleventh refused with 452 4.4.5 (temporary, at MAIL FROM)."""
    st, _, b = put(ctx, doc(ctx, ["alice"], senders=[3]))
    if st != 202:
        return "PUT a document with a fresh sender: HTTP %d %s" % (st, b[:200])
    st, j = cred(ctx, SENDERS[3], SENDER_UUIDS[3], "rate")
    if st != 201:
        return "the sender's credential: HTTP %d" % st
    addr = SENDERS[3] + "@conformance.test"
    s = smtplib.SMTP(ctx.smtp_host, 587, timeout=20)
    try:
        s.starttls(context=CTX)
        s.login(addr, j["secret"])
        for n in range(1, 12):
            stage = "MAIL FROM"
            try:
                c, m = s.mail(addr)
                if c < 300:
                    stage = "RCPT"
                    c, m = s.rcpt("alice@conformance.test")
                if c < 300:
                    stage = "DATA"
                    try:
                        c, m = s.data(("From: %s\r\nTo: alice@conformance.test\r\nSubject: rate %d\r\n\r\nconformance\r\n" % (addr, n)).encode())
                    except smtplib.SMTPDataError as e:
                        c, m = e.smtp_code, e.smtp_error
            except smtplib.SMTPServerDisconnected:
                return "message %d: the server hung up at %s" % (n, stage)
            if n <= 10 and c != 250:
                s.rset()
                return "message %d of the burst: %d %r at %s (want 250)" % (n, c, m[:80], stage)
            if n == 11:
                if c != 452 or b"4.4.5" not in m or stage != "MAIL FROM":
                    return "the eleventh message: %d %r at %s (want 452 4.4.5 at MAIL FROM)" % (c, m[:80], stage)
                return None
    finally:
        try:
            s.quit()
        except smtplib.SMTPException:
            pass
        put(ctx, doc(ctx, ["alice"], senders=[]))
    return "unreachable"


PROTO_CHECKS = [
    ("no_open_relay", check_no_open_relay),
    ("no_auth_on_25", check_no_auth_on_25),
    ("imap_login", check_imap_login),
    ("foreign_from_refused", check_foreign_from),
    ("mail_password_not_api", check_mail_password_not_api),
    ("parking_550_5_1_1", check_parking),
    ("lan_only_sasl_refused", check_lan_only_sasl),
    ("sender_submits_own_from", check_sender_submits_own_from),
    ("sender_foreign_from_refused", check_sender_foreign_from),
    ("sender_inbound_550_5_1_1", check_sender_inbound_refused),
    ("sender_no_imap", check_sender_no_imap),
    ("sender_rate_limit", check_sender_rate_limit),
]
