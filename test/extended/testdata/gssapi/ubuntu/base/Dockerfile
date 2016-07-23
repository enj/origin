# Clone from the Ubuntu 16.04 LTS image
FROM ubuntu:16.04

ARG REALM
ARG HOST

ENV REALM ${REALM}
ENV HOST ${HOST}

ENV CLIENT CLIENT_MISSING_LIBS

ENV OS_ROOT /run/os
ENV KUBECONFIG ${OS_ROOT}/config
ENV PATH ${OS_ROOT}/bin:${PATH}

WORKDIR ${OS_ROOT}
ADD gssapi-tests.sh gssapi-tests.sh
ADD config config
ADD hack hack
ADD oc bin/oc

RUN apt-get update
RUN apt-get install -y bc
