#!/usr/bin/bash

set -e
set -x

echo "I ran this on `uname -a`"

CLIENT_HAS_GSSAPI=true
SERVER_HAS_BASIC=true
users=(user1 user2 user3 user4 user5)

# Client has no GSSAPI and server is GSSAPI only
# Everything fails

if [[ !CLIENT_HAS_GSSAPI && !SERVER_HAS_BASIC ]]
then
    for u in ${users[@]}
    do
        u+=$realm
        os::cmd::expect_failure "echo wrongpassword | kinit $u"
        os::cmd::expect_failure_and_text 'oc login' "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_failure 'kdestroy && exit 1'

        os::cmd::expect_failure "echo password | kinit $u"
        os::cmd::expect_failure_and_text 'oc login' "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_failure 'kdestroy && exit 1'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
    done
fi

# Client has no GSSAPI and server is GSSAPI with Basic fallback
# Only BASIC works

if [[ !CLIENT_HAS_GSSAPI && SERVER_HAS_BASIC ]]
then
    for u in ${users[@]}
    do
        u+=$realm
        os::cmd::expect_failure "echo wrongpassword | kinit $u"
        os::cmd::expect_failure_and_text 'oc login' 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_failure 'kdestroy && exit 1'

        os::cmd::expect_failure "echo password | kinit $u"
        os::cmd::expect_failure_and_text 'oc login' 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_failure 'kdestroy && exit 1'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success "oc login -u $u -p password"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
    done
fi

# Client has GSSAPI and server is GSSAPI only
# Only GSSAPI works

if [[ CLIENT_HAS_GSSAPI && !SERVER_HAS_BASIC ]]
then
    for u in ${users[@]}
    do
        os::cmd::expect_failure "echo wrongpassword | kinit $u"
        os::cmd::expect_failure_and_not_text 'oc login' 'panic'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_success "echo password | kinit $u"
        os::cmd::expect_success_and_text 'oc login' 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_failure_and_text "oc login -u $u -p password" "Can't find client principal $u in cache collection"
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "echo password | kinit $u"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'
    done

    # Having multiple tickets
    os::cmd::expect_success 'echo password | kinit user1'
    os::cmd::expect_success 'echo password | kinit user2'
    os::cmd::expect_success 'echo password | kinit user3'

    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user3' 'Login successful.'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' "Can't find client principal user5$realm in cache collection"

    os::cmd::expect_failure_and_text 'oc login -u user4 -p password' "Can't find client principal user4$realm in cache collection"
    os::cmd::expect_failure_and_text 'oc login -u user5 -p password' "Can't find client principal user5$realm in cache collection"
fi

# Client has GSSAPI and server is GSSAPI with Basic fallback
# Everything works

if [[ CLIENT_HAS_GSSAPI && SERVER_HAS_BASIC ]]
then
    for u in ${users[@]}
    do
        os::cmd::expect_failure "echo wrongpassword | kinit $u"
        os::cmd::expect_failure_and_not_text 'oc login' 'panic'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_success "echo password | kinit $u"
        os::cmd::expect_success_and_text 'oc login' 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'

        os::cmd::expect_failure_and_text "oc login -u $u -p wrongpassword" 'Login failed (401 Unauthorized)'
        os::cmd::expect_failure_and_not_text 'oc whoami' $u

        os::cmd::expect_success "oc login -u $u -p password"
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u

        # Password is ignored if you have the ticket for the user
        os::cmd::expect_success "echo password | kinit $u"
        os::cmd::expect_success_and_text "oc login -u $u -p wrongpassword" 'Login successful.'
        os::cmd::expect_success_and_text 'oc whoami' $u
        os::cmd::expect_success_and_text 'oc logout' $u
        os::cmd::expect_success 'kdestroy'
    done

    # Having multiple tickets
    os::cmd::expect_success 'echo password | kinit user1'
    os::cmd::expect_success 'echo password | kinit user2'
    os::cmd::expect_success 'echo password | kinit user3'

    os::cmd::expect_success_and_text 'oc login -u user1' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user2' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user3' 'Login successful.'

    # Ignore password
    os::cmd::expect_success_and_text 'oc login -u user1 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user2 -p wrongpassword' 'Login successful.'
    os::cmd::expect_success_and_text 'oc login -u user3 -p wrongpassword' 'Login successful.'

    # Using BASIC
    os::cmd::expect_failure_and_text 'oc login -u user4 -p wrongpassword' 'Login failed (401 Unauthorized)'
    os::cmd::expect_failure_and_text 'oc login -u user5 -p wrongpassword' 'Login failed (401 Unauthorized)'

    os::cmd::expect_success 'oc login -u user4 -p password'
    os::cmd::expect_success 'oc login -u user5 -p password'
fi

# os::cmd::expect_success_and_not_text
