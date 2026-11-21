FROM alpine:3.21
RUN apk add --no-cache dnsmasq openssh sudo && adduser -D -s /bin/ash defender && echo 'defender:practice-lab' | chpasswd && echo 'defender ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/defender && chmod 440 /etc/sudoers.d/defender && mkdir -p /run/sshd && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 755 /usr/local/bin/lab-entrypoint
EXPOSE 22 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
