FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server sudo python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd --create-home --shell /bin/bash vagrant \
    && echo 'vagrant:vagrant' | chpasswd \
    && echo 'vagrant ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/vagrant \
    && chmod 440 /etc/sudoers.d/vagrant \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'PubkeyAuthentication yes' \
        'UseDNS no' \
        > /etc/ssh/sshd_config.d/vagrant.conf

COPY vagrant.pub /home/vagrant/.ssh/authorized_keys

RUN chmod 700 /home/vagrant/.ssh \
    && chmod 600 /home/vagrant/.ssh/authorized_keys \
    && chown -R vagrant:vagrant /home/vagrant/.ssh

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
