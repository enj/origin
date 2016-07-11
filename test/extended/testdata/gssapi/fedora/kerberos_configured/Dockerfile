FROM fedora-gssapi-kerberos

# Add conf files for Kerberos
ADD krb5.conf /etc/krb5.conf
ADD configure.sh /configure.sh
RUN bash /configure.sh
