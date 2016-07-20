# Clone from the Fedora 23 image
FROM fedora:23

ENV OS_ROOT /run/os
ENV KUBECONFIG ${OS_ROOT}/config
ENV PATH ${OS_ROOT}/bin:${PATH}

WORKDIR ${OS_ROOT}
ADD gssapi-tests.sh gssapi-tests.sh
ADD config config
ADD hack hack
ADD oc bin/oc

RUN dnf install -y findutils bc
