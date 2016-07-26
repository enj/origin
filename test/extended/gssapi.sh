#!/bin/bash
#
# Extended tests for logging in using GSSAPI

set -o errexit
set -o nounset
set -o pipefail

STARTTIME="$(date +%s)"

PROJECT='gssapiproxy'
TEST_NAME="test-extended/${PROJECT}"

OS_ROOT="$(dirname "${BASH_SOURCE}")/../.."
cd "${OS_ROOT}"
source hack/lib/init.sh

os::build::setup_env

os::util::environment::setup_time_vars
os::util::environment::setup_all_server_vars "${TEST_NAME}"
os::util::environment::use_sudo

os::log::stacktrace::install
os::log::start_system_logger

ensure_iptables_or_die ## TODO Is this needed?

reset_tmp_dir

# Allow setting $JUNIT_REPORT to toggle output behavior
if [[ -n "${JUNIT_REPORT:-}" ]]; then
    export JUNIT_REPORT_OUTPUT="${LOG_DIR}/raw_test_output.log"
fi

# Always keep containers' raw output for simplicity
export JUNIT_GSSAPI_OUTPUT="${LOG_DIR}/raw_test_output_gssapi.log"

os::test::junit::declare_suite_start "${TEST_NAME}"

os::cmd::expect_success 'hack/build-go.sh cmd/oc -tags=gssapi'
os::cmd::expect_success_and_text 'oc version' 'GSSAPI Kerberos SPNEGO'

function cleanup() {
    out=$?
    set +e
    cleanup_openshift

    # TODO(skuznets): un-hack this nonsense once traps are in a better state
    if [[ -n "${JUNIT_REPORT_OUTPUT:-}" ]]; then
      # get the jUnit output file into a workable state in case we crashed in the middle of testing something
      os::test::junit::reconcile_output

      # check that we didn't mangle jUnit output
      os::test::junit::check_test_counters

      # use the junitreport tool to generate us a report
      "${OS_ROOT}/hack/build-go.sh" tools/junitreport
      junitreport="$(os::build::find-binary junitreport)"

      if [[ -z "${junitreport}" ]]; then
          echo "It looks as if you don't have a compiled junitreport binary"
          echo
          echo "If you are running from a clone of the git repo, please run"
          echo "'./hack/build-go.sh tools/junitreport'."
          exit 1
      fi

      cat "${JUNIT_REPORT_OUTPUT}" "${JUNIT_GSSAPI_OUTPUT}"    \
        | "${junitreport}" --type oscmd                        \
                           --suites nested                     \
                           --roots github.com/openshift/origin \
                           --output "${ARTIFACT_DIR}/report.xml"
      cat "${ARTIFACT_DIR}/report.xml" | "${junitreport}" summarize
    fi

    ENDTIME=$(date +%s); echo "$0 took $(($ENDTIME - $STARTTIME)) seconds"
    exit $out
}

function update_auth_proxy_config {
    local server_config="${1}"
    local spec='{.items[0].spec.containers[0].env[?(@.name=="SERVER")].value}'
    spec+='_'
    spec+='{.items[0].spec.containers[0].env[?(@.name=="SERVER_GSSAPI_BASIC_AUTH")].value}'
    spec+='_'
    spec+='{.items[0].status.conditions[?(@.type=="Ready")].status}'

    if [[ "${server_config}" = 'SERVER_GSSAPI_BASIC_FALLBACK' ]]; then
        local SERVER_GSSAPI_BASIC_AUTH=on
    else
        local SERVER_GSSAPI_BASIC_AUTH=off
    fi

    os::cmd::expect_success "oc set env dc/gssapiproxy-server SERVER='${server_config}' SERVER_GSSAPI_BASIC_AUTH='${SERVER_GSSAPI_BASIC_AUTH}'"
    os::cmd::try_until_text "oc get pods -l deploymentconfig=gssapiproxy-server -o jsonpath='${spec}'" "^${server_config}_${SERVER_GSSAPI_BASIC_AUTH}_True$"
}

function run_gssapi_tests() {
    local image_name="${1}"
    local server_config="${2}"
    oc run "${image_name}" \
        --image="${PROJECT}/${image_name}" \
        --generator=run-pod/v1 --restart=Never --attach \
        --env=SERVER="${server_config}" \
        1> "${LOG_DIR}/${image_name}-${server_config}.log" \
        2>> "${JUNIT_GSSAPI_OUTPUT}"
    os::cmd::expect_success_and_text "cat '${LOG_DIR}/${image_name}-${server_config}.log'" 'SUCCESS'
    os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/${image_name}-${server_config}.log'" 'FAILURE'
    os::cmd::expect_success "oc delete pod ${image_name}"
}

trap "cleanup" EXIT

echo "[INFO] Starting server"

configure_os_server

patch='
{
  "oauthConfig": {
    "identityProviders": [{
      "name": "header",
      "challenge": true,
      "mappingMethod": "add",
      "provider": {
        "apiVersion": "v1",
        "kind": "RequestHeaderIdentityProvider",
        "challengeURL": "http://gssapiproxy-server.gssapiproxy.svc.cluster.local/mod_auth/oauth/authorize?${query}",
        "headers": ["Remote-User"]
      }
    }]
  }
}
'
cp "${SERVER_CONFIG_DIR}/master/master-config.yaml" "${SERVER_CONFIG_DIR}/master/master-config.tmp.yaml"
openshift ex config patch "${SERVER_CONFIG_DIR}/master/master-config.tmp.yaml" --patch="${patch}" > "${SERVER_CONFIG_DIR}/master/master-config.yaml"
USE_LATEST_IMAGES=true ## Is this needed?
start_os_server

KUBECONFIG="${ADMIN_KUBECONFIG}"

install_registry
wait_for_registry
REGISTRY_IP="$(oc get svc docker-registry -n default -o jsonpath='{.spec.clusterIP}:{.spec.ports[0].targetPort}')"
# TODO REGISTRY_IP re-add

os::cmd::expect_success 'oc login -u system:admin'
os::cmd::expect_success "oc new-project ${PROJECT}"
os::cmd::expect_success "oadm policy add-scc-to-user anyuid -z default -n ${PROJECT}"

# create all the resources we need
cp -R test/extended/testdata/gssapi "${BASETMPDIR}"
TEST_DATA="${BASETMPDIR}/gssapi"

HOST='gssapiproxy-server.gssapiproxy.svc.cluster.local'
REALM="${HOST^^}"
BACKEND='https://openshift.default.svc.cluster.local:443'

os::cmd::expect_success "oc create -f '${TEST_DATA}/proxy'"

# kick off a build and wait for it to finish
os::cmd::expect_success "oc set env dc/gssapiproxy-server HOST='${HOST}' REALM='${REALM}' BACKEND='${BACKEND}'"
os::cmd::expect_success "oc start-build --from-dir='${TEST_DATA}/proxy' --follow gssapiproxy"

OS_IMAGES=(fedora ubuntu)

for os_image in "${OS_IMAGES[@]}"; do

    pushd "${TEST_DATA}/${os_image}"
        cp "$(which oc)" base
        cp -R "${OS_ROOT}/hack" base
        cp ../scripts/test-wrapper.sh base
        cp ../scripts/gssapi-tests.sh base

        os::cmd::expect_success 'oc create -f base'
        os::cmd::expect_success 'oc create -f kerberos'
        os::cmd::expect_success 'oc create -f kerberos_configured'
    popd

    # TODO Figure out how to set environment variables with binary builds; needed for ${REALM} and ${HOST}

    pushd "${TEST_DATA}/${os_image}"
        # os::cmd::expect_success "oc start-build --from-dir=base --follow '${os_image}-gssapi-base'"
        pushd base
            os::cmd::expect_success "docker build --build-arg REALM='${REALM}' --build-arg HOST='${HOST}' -t '${PROJECT}/${os_image}-gssapi-base:latest' ."
        popd

        # os::cmd::expect_success "oc start-build --from-dir=kerberos --follow '${os_image}-gssapi-kerberos'"
        pushd kerberos
            os::cmd::expect_success "docker build -t '${PROJECT}/${os_image}-gssapi-kerberos:latest' ."
        popd

        # os::cmd::expect_success "oc start-build --from-dir=kerberos_configured --follow '${os_image}-gssapi-kerberos-configured'"
        pushd kerberos_configured
            os::cmd::expect_success "docker build -t '${PROJECT}/${os_image}-gssapi-kerberos-configured:latest' ."
        popd
    popd

done

for server_config in SERVER_GSSAPI_ONLY SERVER_GSSAPI_BASIC_FALLBACK; do

    update_auth_proxy_config "${server_config}"

    for os_image in "${OS_IMAGES[@]}"; do

        run_gssapi_tests "${os_image}-gssapi-base" "${server_config}"

        run_gssapi_tests "${os_image}-gssapi-kerberos" "${server_config}"

        run_gssapi_tests "${os_image}-gssapi-kerberos-configured" "${server_config}"

    done

done

os::test::junit::declare_suite_end
