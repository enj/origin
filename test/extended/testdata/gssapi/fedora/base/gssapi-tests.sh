#!/usr/bin/bash

set -e
set -x

echo "I ran this on `uname -a`"

LOGIN=''
LOGIN_USER_1='-u user1'
LOGIN_USER_2='-u user2'
LOGIN_USER_1_PASS='-u user1 -p password'
LOGIN_USER_2_PASS='-u user2 -p password'
LOGIN_USER_INCORRECT_PASS='-u user1 -p incorrect'

NONE='NONE'
UNCONFIGURED='UNCONFIGURED'
CONFIGURED='CONFIGURED'
TICKET='TICKET'

GSSAPI_ONLY='GSSAPI_ONLY'
GSSAPI_BASIC='GSSAPI_BASIC'

function os::cmd::et::gssapi_login() {
	if [[ $# -ne 4 ]]; then echo "os::cmd::et::gssapi_login expects four arguments, got $#"; exit 1; fi
	local testname=$1
    local args=$2
	local expected_user=$3
    local expected_code=$4

    oc login ${args}
    out_code=$?
    actual_user=`oc whoami`

    if [[ out_code -ne expected_code]]
    then
        echo "${testname} failed: exit code ${out_code} does not match expected code ${expected_code}."
        exit 1
    fi

    if [[ expected_code -e "0" ]]
    then
        if [[expected_user -ne actual_user]]
        then
            echo "${testname} failed: expected user ${expected_user} but got ${actual_user}."
            exit 1
        fi
    fi

}
readonly -f os::cmd::et::gssapi_login

function os::cmd::et::determine_user() {
	if [[ $# -ne 4 ]]; then echo "os::cmd::et::determine_user expects two arguments, got $#"; exit 1; fi
	local testname=$1
    local args=$2
	local expected_user=$3
    local expected_code=$4

}
readonly -f os::cmd::et::determine_user

function os::cmd::et::determine_code() {
	if [[ $# -ne 4 ]]; then echo "os::cmd::et::determine_code expects two arguments, got $#"; exit 1; fi
	local testname=$1
    local args=$2
	local expected_user=$3
    local expected_code=$4

}
readonly -f os::cmd::et::determine_code

CLIENT='T'
SERVER='G'
TEST_NAME_BASE="${CLIENT} ${SERVER} "


OVERALL_RETURN=0
test_args=($LOGIN LOGIN_USER_1 LOGIN_USER_2 LOGIN_USER_1_PASS LOGIN_USER_2_PASS LOGIN_USER_INCORRECT_PASS)

for args in ${test_args[@]}; do

    user=os::cmd::et::determine_user $args $CLIENT $SERVER
    code=os::cmd::et::determine_code $args $CLIENT $SERVER
    set +e
    # use a subshell to prevent `exit` calls from killing this script
    os::cmd::et::gssapi_login "${TEST_NAME_BASE} ${args}" ${args} ${user} ${code}
    CURR_RETURN=$?
    set -e

	if [ "${CURR_RETURN}" -ne "0" ]; then
		OVERALL_RETURN=${CURR_RETURN}
	fi

done

exit ${OVERALL_RETURN}
