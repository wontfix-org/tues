# Test-only sshd image for the tues integration tests.
#
# Users:
#   tues  (password: tuespass)  login user; may sudo to anyone with its password,
#                               and to `nopw` without a password.
#   nopw                        target for the NOPASSWD sudo tests.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash tues \
 && echo 'tues:tuespass' | chpasswd \
 && useradd -m -s /bin/bash nopw \
 && printf 'Defaults lecture=never\ntues ALL=(ALL) ALL\ntues ALL=(nopw) NOPASSWD: ALL\n' > /etc/sudoers.d/tues \
 && chmod 0440 /etc/sudoers.d/tues \
 && ssh-keygen -A

COPY sshd_config /etc/ssh/sshd_config.d/tues.conf
COPY authorized_keys /home/tues/.ssh/authorized_keys
RUN chown -R tues:tues /home/tues/.ssh \
 && chmod 700 /home/tues/.ssh \
 && chmod 600 /home/tues/.ssh/authorized_keys

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
