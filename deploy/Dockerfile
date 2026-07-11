ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN useradd --system --home /var/lib/noosphere --shell /usr/sbin/nologin noosphere
COPY noosd /usr/local/bin/noosd
USER noosphere
VOLUME ["/var/lib/noosphere"]
EXPOSE 9650 9651
ENTRYPOINT ["/usr/local/bin/noosd"]
