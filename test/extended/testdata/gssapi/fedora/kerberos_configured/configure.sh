sed -i.bak1 -e "s/EXAMPLE\.COM/${REALM}/g" /etc/krb5.conf
sed -i.bak2 -e "s/example\.com/${HOST}/g" /etc/krb5.conf
sed -i.bak3 -e "s/#//g" /etc/krb5.conf
