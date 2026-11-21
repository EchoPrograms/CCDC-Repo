ARG ALPINE_VERSION=3.24
FROM alpine:${ALPINE_VERSION} AS gateway
RUN apk add --no-cache socat
COPY lab/alpine/gateway.sh /usr/local/bin/lab-gateway
USER 65534:65534
ENTRYPOINT ["/bin/sh", "/usr/local/bin/lab-gateway"]

FROM alpine:${ALPINE_VERSION} AS builder
RUN apk add --no-cache build-base
COPY lab/alpine/preload.c lab/alpine/diagnostic.c lab/alpine/sleeper.c /src/
RUN mkdir /out \
    && cc -Wall -Wextra -Werror -O2 -fPIC -shared -o /out/libaudit.so /src/preload.c \
    && cc -Wall -Wextra -Werror -O2 -o /out/diagnostic /src/diagnostic.c \
    && cc -Wall -Wextra -Werror -O2 -o /out/lab-sleeper /src/sleeper.c

FROM alpine:${ALPINE_VERSION} AS target
RUN apk add --no-cache openssh sshpass sudo bash openrc acl linux-pam \
    php84 socat iproute2 lsof binutils \
    && addgroup -S sudo \
    && adduser -D -s /bin/bash defender \
    && addgroup defender sudo \
    && adduser -D -s /bin/bash support \
    && adduser -D -H -s /sbin/nologin webapp \
    && mkdir -p /opt/ccdc /opt/lab /usr/local/libexec /etc/sudoers.d \
    && printf 'Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > /etc/sudoers \
    && printf '%%sudo ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/10-defender \
    && chmod 440 /etc/sudoers \
    && chmod 440 /etc/sudoers.d/10-defender \
    && visudo -cf /etc/sudoers
COPY ccdc-hunt.sh /opt/ccdc/ccdc-hunt.sh
COPY hunter-hunt.sh hunter-setup.sh hunter-harden.sh /opt/ccdc/
COPY --from=builder /out/ /opt/lab/bin/
COPY lab/alpine/seed.sh lab/alpine/scenarios.tsv lab/alpine/grade.sh lab/alpine/verify.sh /opt/lab/
COPY lab/alpine/entrypoint.sh /usr/local/bin/lab-entrypoint
COPY lab/alpine/healthcheck.sh /usr/local/bin/lab-healthcheck
RUN chmod 755 /opt/ccdc/ccdc-hunt.sh /opt/ccdc/hunter-hunt.sh /opt/ccdc/hunter-setup.sh /opt/ccdc/hunter-harden.sh /opt/lab/seed.sh /opt/lab/grade.sh \
    /usr/local/bin/lab-entrypoint /usr/local/bin/lab-healthcheck
EXPOSE 22 8080
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
