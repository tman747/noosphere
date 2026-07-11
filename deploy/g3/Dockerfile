ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}
RUN apt-get update \
 && apt-get install --yes --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --home /var/lib/noos-g3 --shell /usr/sbin/nologin noos-g3
WORKDIR /opt/noos-g3
COPY tools/g3/public_duration.py /usr/local/bin/noos-g3-duration
RUN chmod 0555 /usr/local/bin/noos-g3-duration
USER noos-g3
ENTRYPOINT ["python", "/usr/local/bin/noos-g3-duration"]
