# A disposable OpenSSH host for live scan validation (scripts/validation/targets.sh).
#
# No account can log in while no validation run is active. root has no
# password, no key is installed anywhere, and the one audit account is created
# locked: its password field is "!", which matches no password.
#
# live_scan.sh gives that account a throwaway password for the length of one
# run (over `docker exec -i ... chpasswd`, on stdin) and sets it back to "!" when
# the run ends, however it ends. The account may use sudo with that password,
# which is how a credentialed audit elevates; nothing is NOPASSWD.
#
# sudo and iproute2 are here for the credentialed audit: sudo for elevation,
# iproute2 for `ss`, the socket table the collectors read. An unauthenticated
# scan sees neither.
ARG BASE
FROM ${BASE}
ARG AUDIT_USER=ccure-audit
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server sudo iproute2 \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && useradd --create-home --shell /bin/bash "$AUDIT_USER" \
 && usermod --password '!' "$AUDIT_USER" \
 && printf '%s ALL=(ALL:ALL) ALL\n' "$AUDIT_USER" > "/etc/sudoers.d/$AUDIT_USER" \
 && chmod 0440 "/etc/sudoers.d/$AUDIT_USER" \
 && rm -rf /var/lib/apt/lists/*
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
