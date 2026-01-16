FROM --platform=linux/amd64 almalinux:9

LABEL org.opencontainers.image.authors="Dennis Lee <dylee@fnal.gov>"

ARG rucio_version

RUN dnf upgrade -y && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN dnf install -y epel-release.noarch && \
    dnf install -y https://repo.osg-htc.org/osg/25-main/osg-25-main-el9-release-latest.rpm && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN dnf config-manager --set-enabled crb

RUN dnf install -y python3 python3-pip python3-devel \
    openssl-devel vim git \
    gfal2-all python3-gfal2 osg-wn-client && \
    dnf clean all && \
    rm -rf /var/cache/dnf

COPY requirements.txt /requirements.txt

WORKDIR /tmp

RUN pip3 install --no-cache-dir --upgrade pip setuptools && \
    pip3 install --no-cache-dir rucio-clients==$rucio_version && \
    pip3 install --no-cache-dir -r /requirements.txt && \
    pip3 cache purge

COPY scripts /scripts
ENV X509_USER_PROXY=/opt/proxy/x509up
ENTRYPOINT ["/bin/bash", "-c", "sleep infinity"]
