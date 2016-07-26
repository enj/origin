#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

cd "${OS_ROOT}"
source hack/lib/init.sh

export TEST_NAME="test-extended/gssapiproxy-tests/$(uname -n)-${CLIENT}-${SERVER}"
os::util::environment::setup_time_vars
os::util::environment::setup_tmpdir_vars "${TEST_NAME}"
export JUNIT_REPORT_OUTPUT="${LOG_DIR}/raw_test_output.log"
reset_tmp_dir

set +e
# use a subshell to prevent `exit` calls from killing this script
( './gssapi-tests.sh' ) 2>&1
out=$?
set -e

cat "${JUNIT_REPORT_OUTPUT}" 1>&2
exit $out
