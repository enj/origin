FROM gssapiproxy/fedora-gssapi-kerberos

ENV CLIENT CLIENT_HAS_LIBS_IS_CONFIGURED

ADD configure.sh /configure.sh
RUN bash /configure.sh
