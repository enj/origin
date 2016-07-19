#!/usr/bin/bash

set -e
# set -x

echo "I ran this on `uname -a`"

# KEYRING does not work inside of a container since it is part of the kernel
sed -i.bak1 's#KEYRING:persistent:#DIR:/tmp/krb5cc_#' /etc/krb5.conf

export KUBECONFIG=/tmp/config
export OS_ROOT='/var/run/os'
source "${OS_ROOT}/hack/lib/init.sh"
# os::util::environment::update_path_var
export PATH="${OS_ROOT}/_output/local/bin/linux/amd64:${PATH}"

os::test::junit::declare_suite_start "test-extended/gssapiproxy-tests"

SUCCESS='Login successful.'
UNAUTHORIZED='Login failed \(401 Unauthorized\)'

CLIENT_MISSING_LIBS='CLIENT_MISSING_LIBS'
CLIENT_HAS_LIBS='CLIENT_HAS_LIBS'
CLIENT_HAS_LIBS_IS_CONFIGURED='CLIENT_HAS_LIBS_IS_CONFIGURED'

SERVER_GSSAPI_ONLY='SERVER_GSSAPI_ONLY'
SERVER_GSSAPI_BASIC_FALLBACK='SERVER_GSSAPI_BASIC_FALLBACK'

CLIENT=$CLIENT_HAS_LIBS_IS_CONFIGURED
SERVER=$SERVER_GSSAPI_ONLY

users=(user1 user2 user3 user4 user5)
realm='@GSSAPIPROXY-SERVER.GSSAPIPROXY.SVC.CLUSTER.LOCAL'

# Client has no GSSAPI libs and server is GSSAPI only
# Everything fails
# Errors do NOT mention Kerberos

if [[ $CLIENT == $CLIENT_MISSING_LIBS && $SERVER == $SERVER_GSSAPI_ONLY ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p password" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'An invalid name was supplied'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" 'An invalid name was supplied'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
    done
fi

# Client has no GSSAPI libs and server is GSSAPI with Basic fallback
# Only BASIC works
# Errors do NOT mention Kerberos

if [[ $CLIENT == $CLIENT_MISSING_LIBS && $SERVER == $SERVER_GSSAPI_BASIC_FALLBACK ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure_and_text 'oc login' "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text 'oc login' "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success_and_text "oc login -u $full -p password" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        os::cmd::expect_success_and_text "oc login -u $u -p password" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
    done
fi

# Client has uncofigured GSSAPI libs and server is GSSAPI only
# Everything fails
# Errors mention Kerberos

if [[ $CLIENT == $CLIENT_HAS_LIBS && $SERVER == $SERVER_GSSAPI_ONLY ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p password" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'An invalid name was supplied'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" 'An invalid name was supplied'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
    done
fi

# Client has unconfigured GSSAPI libs and server is GSSAPI with Basic fallback
# Only BASIC works
# Errors do NOT mention Kerberos

if [[ $CLIENT == $CLIENT_HAS_LIBS && $SERVER == $SERVER_GSSAPI_BASIC_FALLBACK ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure_and_text 'oc login <<< \n' "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text 'oc login <<< \n' "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success_and_text "oc login -u $full -p password" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        os::cmd::expect_success_and_text "oc login -u $u -p password" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        os::cmd::try_until_text 'oc whoami' 'system:anonymous'
    done
fi

# Client has GSSAPI configured and server is GSSAPI only
# Only GSSAPI works
# Errors mention Kerberos

if [[ $CLIENT == $CLIENT_HAS_LIBS_IS_CONFIGURED && $SERVER == $SERVER_GSSAPI_ONLY ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure "kinit $u <<< wrongpassword"
        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy -A'

        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text 'oc login' "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy -A'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" "Can't find client principal $full in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy -A'
    done

    # Having multiple tickets
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success 'kinit user2 <<< password'
    os::cmd::expect_success 'kinit user3 <<< password'

    os::cmd::expect_success_and_text 'oc login -u user1' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' "Can't find client principal user5$realm in cache collection"

    os::cmd::expect_failure_and_text 'oc login -u user4 -p password' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p password' "Can't find client principal user5$realm in cache collection"

    # Cleanup
    os::cmd::expect_success 'kdestroy -A'
    os::cmd::expect_success_and_text 'oc logout' 'user3'

    # Make sure things work if realm is or is not given
    os::cmd::expect_success 'kinit user4 <<< password'
    os::cmd::expect_success_and_text 'oc login -u user4' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'
    os::cmd::expect_success_and_text "oc login -u user4$realm" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'

    os::cmd::expect_success "kinit user5$realm <<< password"
    os::cmd::expect_success_and_text 'oc login -u user5' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success_and_text "oc login -u user5$realm" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success 'kdestroy -A'

    # Broad test with multiple users
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success "kinit user2$realm <<< password"

    os::cmd::expect_failure_and_text 'oc login -u user3 -p password' "Can't find client principal user3$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user3'

    os::cmd::expect_failure_and_text "oc login -u user4$realm -p password" "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_success_and_text "oc login -u user1$realm" "${SUCCESS}" ##TODO
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc logout' 'user1'

    os::cmd::expect_success_and_text 'oc login -u user2' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc logout' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user5' "Can't find client principal user5$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::cmd::expect_failure_and_text "oc login -u user5$realm" "Can't find client principal user5$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
fi

# Client has GSSAPI configured and server is GSSAPI with Basic fallback
# Everything works
# Errors do NOT mention Kerberos

if [[ $CLIENT == $CLIENT_HAS_LIBS_IS_CONFIGURED && $SERVER == $SERVER_GSSAPI_BASIC_FALLBACK ]]; then
    for u in "${users[@]}"; do
        os::cmd::expect_failure "kinit $u <<< wrongpassword"
        os::cmd::expect_failure_and_text 'oc login <<< \n' "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy -A'

        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text 'oc login' "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy -A'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "${UNAUTHORIZED}"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success_and_text "oc login -u $u -p password" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" "${SUCCESS}"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy -A'
    done

    # Having multiple tickets
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success 'kinit user2 <<< password'
    os::cmd::expect_success 'kinit user3 <<< password'

    os::cmd::expect_success_and_text 'oc login -u user1' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' "${UNAUTHORIZED}"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' "${UNAUTHORIZED}"

    os::cmd::expect_success_and_text 'oc login -u user4 -p password' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc login -u user5 -p password' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user5'

    # Cleanup
    os::cmd::expect_success 'kdestroy -A'
    os::cmd::expect_success_and_text 'oc logout' 'user5'

    # Make sure things work if realm is or is not given
    os::cmd::expect_success 'kinit user4 <<< password'
    os::cmd::expect_success_and_text 'oc login -u user4' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'
    os::cmd::expect_success_and_text "oc login -u user4$realm" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'

    os::cmd::expect_success "kinit user5$realm <<< password"
    os::cmd::expect_success_and_text 'oc login -u user5' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success_and_text "oc login -u user5$realm" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success 'kdestroy -A'

    # Broad test with multiple users
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success "kinit user2$realm <<< password"

    os::cmd::expect_success_and_text 'oc login -u user3 -p password' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user3'
    os::cmd::expect_success_and_text 'oc logout' 'user3'

    os::cmd::expect_success_and_text "oc login -u user4$realm -p password" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'

    os::cmd::expect_success_and_text "oc login -u user1$realm" "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc logout' 'user1'

    os::cmd::expect_success_and_text 'oc login -u user2' "${SUCCESS}"
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc logout' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user5 <<EOF
    EOF' "${UNAUTHORIZED}"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::cmd::expect_failure_and_text "oc login -u user5$realm <<EOF
    EOF" "${UNAUTHORIZED}"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
fi

os::test::junit::declare_suite_end

# os::cmd::expect_success_and_not_text
