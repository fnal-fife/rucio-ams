ARG rucio_version=38.5.5

FROM --platform=linux/amd64 rucio/rucio-clients:release-${rucio_version}

LABEL org.opencontainers.image.authors="Dennis Lee <dylee@fnal.gov>"

RUN dnf upgrade -y && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN dnf install -y epel-release.noarch && \
    dnf install -y https://repo.osg-htc.org/osg/25-main/osg-25-main-el9-release-latest.rpm && \
    dnf clean all && \
    rm -rf /var/cache/dnf

RUN dnf config-manager --set-enabled crb

RUN dnf install -y vim osg-wn-client && \
    dnf clean all && \
    rm -rf /var/cache/dnf

WORKDIR /tmp

COPY scripts /scripts
ENV X509_USER_PROXY=/opt/proxy/x509up
ENTRYPOINT ["/opt/user/entrypoint.sh"]
CMD ["bash"]
