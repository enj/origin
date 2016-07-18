# Clone from the Fedora 23 image
FROM fedora:23

ADD gssapi-tests.sh /gssapi-tests.sh
ADD config /config.yaml

RUN dnf install -y findutils bc

VOLUME /var/run/os
