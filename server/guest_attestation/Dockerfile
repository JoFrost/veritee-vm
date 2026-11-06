FROM python:3.11.15-slim-bookworm@sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15 AS python-dependencies

WORKDIR /tmp

ENV SOURCE_DATE_EPOCH=946684800 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml poetry.lock requirements.lock requirements.sources.sha256 /tmp/
RUN sha256sum -c requirements.sources.sha256 && \
    python -m venv /opt/guest-attestation && \
    /opt/guest-attestation/bin/pip install --no-cache-dir --no-compile \
        --require-hashes --only-binary=:all: --no-deps -r requirements.lock && \
    /opt/guest-attestation/bin/pip check

FROM python:3.11.15-slim-bookworm@sha256:77923445c077d8eb971b14b2b114a1d9cd4a87edb4c75654820ca4832ee8cb15

ARG DEBIAN_SNAPSHOT=20260928T000000Z
ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=946684800 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/guest-attestation/bin:$PATH"

# The pinned Python image already contains the CA bundle needed for HTTPS.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm-updates main" \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
        > /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends tpm2-tools=5.4-1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    rm -f /var/cache/ldconfig/aux-cache \
        /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log

WORKDIR /code

COPY --from=python-dependencies /opt/guest-attestation /opt/guest-attestation
COPY requirements.lock /code/requirements.lock
RUN python -m pip check
COPY ./veritee_attestation /code/veritee_attestation

WORKDIR /code/veritee_attestation
CMD ["python3", "document.py"]
