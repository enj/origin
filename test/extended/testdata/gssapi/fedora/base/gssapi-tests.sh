#!/usr/bin/bash

set -e
set -x

echo "I ran this on `uname -a`"

os::test::junit::declare_suite_start "test-extended/gssapiproxy-tests"

CLIENT_HAS_GSSAPI=true
SERVER_HAS_BASIC=true
users=(user1 user2 user3 user4 user5)

# Client has no GSSAPI and server is GSSAPI only
# Everything fails

if [[ -z CLIENT_HAS_GSSAPI && -z SERVER_HAS_BASIC ]]; then
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

# Client has no GSSAPI and server is GSSAPI with Basic fallback
# Only BASIC works

if [[ -z CLIENT_HAS_GSSAPI && -n SERVER_HAS_BASIC ]]; then
    for u in "${users[@]}"; do
        full="$u$realm"
        os::cmd::expect_failure_and_text 'oc login' 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text 'oc login' 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $full -p wrongpassword" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success_and_text "oc login -u $full -p password" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        os::cmd::expect_success_and_text "oc login -u $u -p password" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
    done
fi

# Client has GSSAPI and server is GSSAPI only
# Only GSSAPI works

if [[ -n CLIENT_HAS_GSSAPI && -z SERVER_HAS_BASIC ]]; then
    for u in "${users[@]}"; do
        os::cmd::expect_failure "kinit $u <<< wrongpassword"
        os::cmd::expect_failure_and_text 'oc login' 'No Kerberos credentials available'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text 'oc login' 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'
    done

    # Having multiple tickets
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success 'kinit user2 <<< password'
    os::cmd::expect_success 'kinit user3 <<< password'

    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' "Can't find client principal user5$realm in cache collection"

    os::cmd::expect_failure_and_text 'oc login -u user4 -p password' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p password' "Can't find client principal user5$realm in cache collection"

    # Cleanup
    os::cmd::expect_success 'kdestroy'
    os::cmd::expect_success_and_text 'oc logout' 'user5'

    # Make sure things work if realm is or is not given
    os::cmd::expect_success 'kinit user4 <<< password'
    os::cmd::expect_success_and_text 'oc login -u user4' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'
    os::cmd::expect_success_and_text "oc login -u user4$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'

    os::cmd::expect_success "kinit user5$realm <<< password"
    os::cmd::expect_success_and_text 'oc login -u user5' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success_and_text "oc login -u user5$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success 'kdestroy'

    # Broad test with multiple users
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success "kinit user2$realm <<< password"

    os::cmd::expect_failure_and_text 'oc login -u user3 -p password' "Can't find client principal user3$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user3'

    os::cmd::expect_failure_and_text "oc login -u user4$realm -p password" "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user4'

    os::cmd::expect_success_and_text "oc login -u user1$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc logout' 'user1'

    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc logout' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user5' "Can't find client principal user5$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::cmd::expect_failure_and_text "oc login -u user5$realm" "Can't find client principal user5$realm in cache collection"
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
fi

# Client has GSSAPI and server is GSSAPI with Basic fallback
# Everything works

if [[ -n CLIENT_HAS_GSSAPI && -n SERVER_HAS_BASIC ]]; then
    for u in "${users[@]}"; do
        os::cmd::expect_failure "kinit $u <<< wrongpassword"
        os::cmd::expect_failure_and_text 'oc login' 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text 'oc login' 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success_and_text "oc login -u $u -p password" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "kinit $u <<< password"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'
    done

    # Having multiple tickets
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success 'kinit user2 <<< password'
    os::cmd::expect_success 'kinit user3 <<< password'

    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user3'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' 'Login failed (401 Unauthorized)'
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' 'Login failed (401 Unauthorized)'

    os::cmd::expect_success_and_text 'oc login -u user4 -p password' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc login -u user5 -p password' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user5'

    # Cleanup
    os::cmd::expect_success 'kdestroy'
    os::cmd::expect_success_and_text 'oc logout' 'user5'

    # Make sure things work if realm is or is not given
    os::cmd::expect_success 'kinit user4 <<< password'
    os::cmd::expect_success_and_text 'oc login -u user4' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'
    os::cmd::expect_success_and_text "oc login -u user4$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'

    os::cmd::expect_success "kinit user5$realm <<< password"
    os::cmd::expect_success_and_text 'oc login -u user5' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success_and_text "oc login -u user5$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user5'
    os::cmd::expect_success_and_text 'oc logout' 'user5'
    os::cmd::expect_success 'kdestroy'

    # Broad test with multiple users
    os::cmd::expect_success 'kinit user1 <<< password'
    os::cmd::expect_success "kinit user2$realm <<< password"

    os::cmd::expect_success_and_text 'oc login -u user3 -p password' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user3'
    os::cmd::expect_success_and_text 'oc logout' 'user3'

    os::cmd::expect_success_and_text "oc login -u user4$realm -p password" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user4'
    os::cmd::expect_success_and_text 'oc logout' 'user4'

    os::cmd::expect_success_and_text "oc login -u user1$realm" 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user1'
    os::cmd::expect_success_and_text 'oc logout' 'user1'

    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc whoami' 'user2'
    os::cmd::expect_success_and_text 'oc logout' 'user2'

    os::cmd::expect_failure_and_text 'oc login -u user5' 'Login failed (401 Unauthorized)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'

    os::cmd::expect_failure_and_text "oc login -u user5$realm" 'Login failed (401 Unauthorized)'
    os::cmd::expect_failure_and_not_text 'oc whoami' 'user5'
fi

os::test::junit::declare_suite_end

# os::cmd::expect_success_and_not_text
