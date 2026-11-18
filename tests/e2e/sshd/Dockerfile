# e2e-ssh (ci.yml): an SSH server for the Portcullis CLI's host agent —
# web-1 is enrolled (managed), web-2 trusts the CA by `host trust`
# (unmanaged). The `portcullis` binary comes out of the Hub image under
# test (docker cp, root-owned), never from here.
FROM docker.io/library/debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get -qq update \
 && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends openssh-server sudo passwd procps ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && ssh-keygen -A \
 && useradd -m -s /bin/bash breakglass && install -d -o breakglass -g breakglass -m 0700 /home/breakglass/.ssh \
 && useradd -m -s /bin/bash deploy \
 && printf 'PerSourcePenalties no\nLogLevel VERBOSE\n' > /etc/ssh/sshd_config.d/00-e2e.conf
# PerSourcePenalties no: every test login comes from the runner's one
# address (OpenSSH 10 would refuse the logins after the refused ones).
# LogLevel VERBOSE: sshd logs each certificate's key id (bob_deploy_keyid).
# sshd -D writes no pid file: the shell records its pid, then becomes sshd
# (the agent's --service none reload signals it).
CMD ["/bin/sh", "-c", "echo $$ > /run/sshd.pid; exec /usr/sbin/sshd -D -e"]
