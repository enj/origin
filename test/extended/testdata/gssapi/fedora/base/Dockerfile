# Clone from the Fedora 23 image
FROM fedora:23

ADD gssapi-tests.sh /tmp/gssapi-tests.sh
ADD config /tmp/config

RUN dnf install -y findutils bc

VOLUME /var/run/os
