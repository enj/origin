FROM gssapiproxy/fedora-gssapi-kerberos

ENV CLIENT CLIENT_HAS_LIBS_IS_CONFIGURED

# Add conf files for Kerberos
ADD krb5.conf /etc/krb5.conf
ADD configure.sh /configure.sh
RUN bash /configure.sh
