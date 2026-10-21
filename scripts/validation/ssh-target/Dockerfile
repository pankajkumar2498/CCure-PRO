# A disposable OpenSSH host for live scan validation (scripts/validation/targets.sh).
# No account can log in: root has no password, and no user or key is added. The
# scan only needs the banner and the key exchange, which is what an
# unauthenticated audit of a Linux host sees.
ARG BASE
FROM ${BASE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && rm -rf /var/lib/apt/lists/*
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
