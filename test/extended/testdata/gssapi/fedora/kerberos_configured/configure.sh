export host='gssapiproxy-server.gssapiproxy.svc.cluster.local'
export realm=`echo ${host} | tr [a-z] [A-Z]`

sed -i.bak1 -e "s/EXAMPLE\.COM/$realm/g" /etc/krb5.conf
sed -i.bak2 -e "s/example\.com/$host/g" /etc/krb5.conf