#!/usr/bin/bash

set -o errexit
set -o nounset
set -o pipefail

echo "GSSAPI tests ran on `uname -n` with ${CLIENT} and ${SERVER}"

# KEYRING does not work inside of a container since it is part of the kernel
sed -i.bak1 's#KEYRING:persistent:#DIR:/tmp/krb5cc_#' /etc/krb5.conf

cd ${OS_ROOT}
source hack/lib/init.sh

trap os::test::junit::reconcile_output EXIT
TEST_NAME='test-extended/gssapiproxy-tests'
os::test::junit::declare_suite_start "${TEST_NAME}"

# Client has no GSSAPI libs and server is GSSAPI only
# Everything fails
# Errors do NOT mention Kerberos

if [[ "${CLIENT}" = 'CLIENT_MISSING_LIBS' && "${SERVER}" = 'SERVER_GSSAPI_ONLY' ]]; then

    os::test::junit::declare_suite_start "${TEST_NAME}/${CLIENT}-${SERVER}"

    os::cmd::expect_failure_and_text 'oc login' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_text 'oc whoami' 'system:anonymous'

    os::cmd::expect_failure_and_text 'oc login -u user1' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user1'

    os::cmd::expect_failure_and_text 'oc login -u user2 -p wrongpassword' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user2 -p password' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user2'

    os::cmd::expect_failure_and_text "oc login -u user3@${REALM}" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user3'

    os::cmd::expect_failure_and_text "oc login -u user4@${REALM} -p wrongpassword" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_failure_and_text "oc login -u user5@${REALM} -p password" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::test::junit::declare_suite_end

fi

# Client has no GSSAPI libs and server is GSSAPI with Basic fallback
# Only BASIC works
# Errors do NOT mention Kerberos

# Should be same as CLIENT_HAS_LIBS

# if [[ "${CLIENT}" = 'CLIENT_MISSING_LIBS' && "${SERVER}" = 'SERVER_GSSAPI_BASIC_FALLBACK' ]]; then
#     for u in "${users[@]}"; do
#         full="$u$realm"
#         os::cmd::expect_failure_and_text 'oc login' 'Login failed \(401 Unauthorized\)'
#         os::cmd::expect_failure_and_not_text 'oc whoami' $u

#         os::cmd::expect_failure_and_text 'oc login' 'Login failed \(401 Unauthorized\)'
#         os::cmd::expect_failure_and_not_text 'oc whoami' $u

#         os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" 'Login failed \(401 Unauthorized\)'
#         os::cmd::expect_failure_and_not_text 'oc whoami' $u

#         os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'Login failed \(401 Unauthorized\)'
#         os::cmd::expect_failure_and_not_text 'oc whoami' $u

#         os::cmd::expect_success_and_text "oc login -u $full -p password" 'Login successful.'
#         os::cmd::expect_success_and_text 'oc whoami' $u
#         os::cmd::expect_success_and_text 'oc logout' $u

#         os::cmd::expect_success_and_text "oc login -u $u -p password" 'Login failed \(401 Unauthorized\)'
#         os::cmd::expect_failure_and_not_text 'oc whoami' $u
#     done
# fi

# Client has uncofigured GSSAPI libs and server is GSSAPI only
# Everything fails
# Errors mention Kerberos

if [[ "${CLIENT}" = 'CLIENT_HAS_LIBS' && "${SERVER}" = 'SERVER_GSSAPI_ONLY' ]]; then

    os::test::junit::declare_suite_start "${TEST_NAME}/${CLIENT}-${SERVER}"

    os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
    os::cmd::expect_failure_and_text 'oc whoami' 'system:anonymous'

    os::cmd::expect_failure_and_text 'oc login -u user1' 'An invalid name was supplied'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user1'

    os::cmd::expect_failure_and_text 'oc login -u user2 -p wrongpassword' 'An invalid name was supplied'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user2 -p password' 'An invalid name was supplied'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user2'

    os::cmd::expect_failure_and_text "oc login -u user3@${REALM}" "Can't find client principal user3@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user3'

    os::cmd::expect_failure_and_text "oc login -u user4@${REALM} -p wrongpassword" "Can't find client principal user4@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_failure_and_text "oc login -u user5@${REALM} -p password" "Can't find client principal user5@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::test::junit::declare_suite_end

fi

# Client has unconfigured GSSAPI libs and server is GSSAPI with Basic fallback
# Only BASIC works
# Errors do NOT mention Kerberos

if [[ ( "${CLIENT}" = 'CLIENT_MISSING_LIBS' || "${CLIENT}" = 'CLIENT_HAS_LIBS' ) && "${SERVER}" = 'SERVER_GSSAPI_BASIC_FALLBACK' ]]; then

    os::test::junit::declare_suite_start "${TEST_NAME}/${CLIENT}-${SERVER}"

    os::cmd::expect_failure_and_text 'oc login <<< \n' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_text 'oc whoami' 'system:anonymous'

    os::cmd::expect_failure_and_text 'oc login -u user1 <<EOF
    EOF' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user1'

    os::cmd::expect_failure_and_text 'oc login -u user2 -p wrongpassword' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user2'

    os::cmd::expect_success_and_text 'oc login -u user2 -p password' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user2@${REALM}"
    os::cmd::try_until_text 'oc whoami' 'system:anonymous' # Make sure token is gone

    os::cmd::expect_failure_and_text "oc login -u user3@${REALM} <<EOF
    EOF" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user3'

    os::cmd::expect_failure_and_text "oc login -u user4@${REALM} -p wrongpassword" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_success_and_text "oc login -u user5@${REALM} -p password" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user5@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user5@${REALM}"

    os::test::junit::declare_suite_end

fi

# Client has GSSAPI configured and server is GSSAPI only
# Only GSSAPI works
# Errors mention Kerberos

if [[ "${CLIENT}" = 'CLIENT_HAS_LIBS_IS_CONFIGURED' && "${SERVER}" = 'SERVER_GSSAPI_ONLY' ]]; then

    os::test::junit::declare_suite_start "${TEST_NAME}/${CLIENT}-${SERVER}"

    # No ticket
    os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
    os::cmd::expect_failure_and_text 'oc whoami' 'system:anonymous'

    os::cmd::expect_failure 'kinit user1 <<< wrongpassword'
    os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user1'

    # Single ticket
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success_and_text 'oc login' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"

    # Having multiple tickets
    os::cmd::expect_success "kinit user2@${REALM} <<< password"
    os::cmd::expect_success 'kinit user3 <<< password'
    os::cmd::expect_failure 'kinit user4 <<< wrongpassword'
    os::cmd::expect_failure "kinit user5@${REALM} <<< wrongpassword"

    # Shortname, non-default ticket
    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"

    # Longname, non-default ticket
    os::cmd::expect_success_and_text "oc login -u user2@${REALM}" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user2@${REALM}"

    # Default ticket
    os::cmd::expect_success_and_text 'oc login' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user3@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user3@${REALM}"

    # Non-ticket users
    os::cmd::expect_failure_and_text 'oc login -u user4' "Can't find client principal user4@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'
    os::cmd::expect_failure_and_text "oc login -u user4@${REALM}" "Can't find client principal user4@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_failure_and_text 'oc login -u user4 -p password' "Can't find client principal user4@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'
    os::cmd::expect_failure_and_text "oc login -u user4@${REALM} -p password" "Can't find client principal user4@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' "Can't find client principal user5@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
    os::cmd::expect_failure_and_text "oc login -u user5@${REALM} -p wrongpassword" "Can't find client principal user5@${REALM} in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    # Password is ignored if you have the ticket for the user
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user3@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user3@${REALM}"

    os::test::junit::declare_suite_end

fi

# Client has GSSAPI configured and server is GSSAPI with Basic fallback
# Everything works
# Errors do NOT mention Kerberos

if [[ "${CLIENT}" = 'CLIENT_HAS_LIBS_IS_CONFIGURED' && "${SERVER}" = 'SERVER_GSSAPI_BASIC_FALLBACK' ]]; then

    os::test::junit::declare_suite_start "${TEST_NAME}/${CLIENT}-${SERVER}"

    # No ticket
    os::cmd::expect_failure_and_text 'oc login <<< \n' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_text 'oc whoami' 'system:anonymous'

    os::cmd::expect_failure 'kinit user1 <<< wrongpassword'
    os::cmd::expect_failure_and_text 'oc login <<< \n' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user1'

    # Single ticket
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success_and_text 'oc login' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"

    # Having multiple tickets
    os::cmd::expect_success "kinit user2@${REALM} <<< password"
    os::cmd::expect_success 'kinit user3 <<< password'
    os::cmd::expect_failure 'kinit user4 <<< wrongpassword'
    os::cmd::expect_failure "kinit user5@${REALM} <<< wrongpassword"

    # Shortname, non-default ticket
    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"

    # Longname, non-default ticket
    os::cmd::expect_success_and_text "oc login -u user2@${REALM}" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user2@${REALM}"

    # Default ticket
    os::cmd::expect_success_and_text 'oc login' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user3@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user3@${REALM}"

    # Non-ticket users
    os::cmd::expect_failure_and_text 'oc login -u user4 <<EOF
    EOF' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'
    os::cmd::expect_failure_and_text "oc login -u user4@${REALM} <<EOF
    EOF" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_success_and_text 'oc login -u user4 -p password' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user4@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user4@${REALM}"
    os::cmd::expect_success_and_text "oc login -u user4@${REALM} -p password" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user4@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user4@${REALM}"

    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
    os::cmd::expect_failure_and_text "oc login -u user5@${REALM} -p wrongpassword" 'Login failed \(401 Unauthorized\)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    # Password is ignored if you have the ticket for the user
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user1@${REALM}"
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user2@${REALM}"
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' "user3@${REALM}"
    os::cmd::expect_success_and_text 'oc logout' "user3@${REALM}"

    os::test::junit::declare_suite_end

fi

os::test::junit::declare_suite_end
