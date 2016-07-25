#!/bin/bash
#
# Extended tests for logging in using GSSAPI

set -o errexit
set -o nounset
set -o pipefail

OS_ROOT="$(dirname "${BASH_SOURCE}")/../.."
cd "${OS_ROOT}"
source hack/lib/init.sh

os::build::setup_env

os::util::environment::setup_time_vars
os::util::environment::setup_all_server_vars "test-extended/gssapiproxy"
os::util::environment::use_sudo

os::log::stacktrace::install
os::log::start_system_logger

ensure_iptables_or_die ## TODO Is this needed?

reset_tmp_dir
JUNIT_REPORT_OUTPUT="${LOG_DIR}/raw_test_output.log"
JUNIT_GSSAPI_OUTPUT="${LOG_DIR}/raw_test_output_gssapi.log"

os::test::junit::declare_suite_start "test-extended/gssapiproxy"

hack/build-go.sh cmd/oc -tags=gssapi
os::cmd::expect_success_and_text 'oc version' 'GSSAPI Kerberos SPNEGO'

function cleanup() {
    out=$?
    os::test::junit::reconcile_output
    cleanup_openshift

    # use the junitreport tool to generate us a report
    "${OS_ROOT}/hack/build-go.sh" tools/junitreport
    junitreport="$(os::build::find-binary junitreport)"

    cat "${JUNIT_REPORT_OUTPUT}" "${JUNIT_GSSAPI_OUTPUT}"   \
    | "${junitreport}"  --type oscmd                        \
                        --suites nested                     \
                        --roots github.com/openshift/origin \
                        --output "${ARTIFACT_DIR}/report.xml"
    cat "${ARTIFACT_DIR}/report.xml" | "${junitreport}" summarize

    echo "[INFO] Exiting"
    [[ -n "${SKIP_TEARDOWN-}" ]] && oc project gssapiproxy ##TODO remove
    return $out
}

function wait_for_auth_proxy() {
    local server_config="${1}"
    local spec='{.items[0].spec.containers[0].env[?(@.name=="SERVER")].value}_{.items[0].status.conditions[?(@.type=="Ready")].status}'
    os::cmd::try_until_text "oc get pods -l deploymentconfig=gssapiproxy-server -o jsonpath='${spec}'" "^${server_config}_True$"
}

function run_gssapi_tests() {
    local image_name="${1}"
    local server_config="${2}"
    oc run "${image_name}" \
        --image="gssapiproxy/${image_name}" \
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

oc login -u system:admin
oc new-project gssapiproxy
oadm policy add-scc-to-user anyuid -z default -n gssapiproxy

# create all the resources we need
cp -R test/extended/testdata/gssapi "${BASETMPDIR}"
TEST_DATA="${BASETMPDIR}/gssapi"

HOST='gssapiproxy-server.gssapiproxy.svc.cluster.local'
REALM="${HOST^^}"
BACKEND='https://openshift.default.svc.cluster.local'

oc create -f "${TEST_DATA}/proxy"

# kick off a build and wait for it to finish
oc set env dc/gssapiproxy-server HOST="${HOST}" REALM="${REALM}" BACKEND="${BACKEND}"
oc start-build --from-dir="${TEST_DATA}/proxy" --follow gssapiproxy

OS_IMAGES=(fedora ubuntu)

for os_image in "${OS_IMAGES[@]}"; do

    pushd "${TEST_DATA}/${os_image}"
        cp "$(which oc)" base
        cp -R "${OS_ROOT}/hack" base
        cp ../scripts/test-wrapper.sh base
        cp ../scripts/gssapi-tests.sh base

        oc create -f base
        oc create -f kerberos
        oc create -f kerberos_configured
    popd

    # TODO Figure out how to set environment variables with binary builds; needed for ${REALM} and ${HOST}

    pushd "${TEST_DATA}/${os_image}"
        # oc start-build --from-dir=base --follow "${os_image}-gssapi-base"
        pushd base
            docker build --build-arg REALM="${REALM}" --build-arg HOST="${HOST}" -t "gssapiproxy/${os_image}-gssapi-base:latest" .
        popd

        # oc start-build --from-dir=kerberos --follow "${os_image}-gssapi-kerberos"
        pushd kerberos
            docker build -t "gssapiproxy/${os_image}-gssapi-kerberos:latest" .
        popd

        # oc start-build --from-dir=kerberos_configured --follow "${os_image}-gssapi-kerberos-configured"
        pushd kerberos_configured
            docker build -t "gssapiproxy/${os_image}-gssapi-kerberos-configured:latest" .
        popd
    popd

done

for server_config in SERVER_GSSAPI_ONLY SERVER_GSSAPI_BASIC_FALLBACK; do

    oc set env dc/gssapiproxy-server SERVER="${server_config}"
    wait_for_auth_proxy "${server_config}"

    for os_image in "${OS_IMAGES[@]}"; do

        run_gssapi_tests "${os_image}-gssapi-base" "${server_config}"

        run_gssapi_tests "${os_image}-gssapi-kerberos" "${server_config}"

        run_gssapi_tests "${os_image}-gssapi-kerberos-configured" "${server_config}"

    done

done

os::test::junit::declare_suite_end
