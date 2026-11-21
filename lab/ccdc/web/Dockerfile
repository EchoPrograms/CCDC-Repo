FROM php:8.3-apache
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo cron gcc libc6-dev && docker-php-ext-install pdo_mysql && rm -rf /var/lib/apt/lists/*
COPY app.php /var/www/html/index.php
COPY maintenance.php /var/www/html/.maintenance.php
COPY marker.c /tmp/marker.c
COPY setup.sh /tmp/setup.sh
COPY entrypoint.sh /usr/local/bin/lab-entrypoint
RUN sh /tmp/setup.sh && chmod 755 /usr/local/bin/lab-entrypoint
EXPOSE 22 80
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
