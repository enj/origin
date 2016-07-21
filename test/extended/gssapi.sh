#!/bin/bash
#
# Extended tests for logging in using GSSAPI

set -o errexit
set -o nounset
set -o pipefail

OS_ROOT=$(dirname "${BASH_SOURCE}")/../..
cd "${OS_ROOT}"
source hack/lib/init.sh

os::log::stacktrace::install
trap os::test::junit::reconcile_output EXIT
os::test::junit::declare_suite_start "test-extended/gssapiproxy"
os::util::environment::setup_time_vars
os::build::setup_env

hack/build-go.sh cmd/oc -tags=gssapi
os::cmd::expect_success_and_text 'oc version' 'GSSAPI Kerberos SPNEGO'

function cleanup() {
    out=$?
    cleanup_openshift
    echo "[INFO] Exiting"
    oc project gssapiproxy
    return $out
}

function wait_for_auth_proxy() {
    local server_config=${1}
    local spec='{.items[0].spec.containers[0].env[?(@.name=="SERVER")].value}_{.items[0].status.conditions[?(@.type=="Ready")].status}'
    os::cmd::try_until_text "oc get pods -l deploymentconfig=gssapiproxy-server -o jsonpath='${spec}'" "^${server_config}_True$"
}

trap "exit" INT TERM
trap "cleanup" EXIT

echo "[INFO] Starting server"

ensure_iptables_or_die
os::util::environment::setup_all_server_vars "test-extended/gssapiproxy"
os::util::environment::use_sudo
reset_tmp_dir

os::log::start_system_logger

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
cp ${SERVER_CONFIG_DIR}/master/master-config.yaml ${SERVER_CONFIG_DIR}/master/master-config.tmp.yaml
openshift ex config patch ${SERVER_CONFIG_DIR}/master/master-config.tmp.yaml --patch="${patch}" > ${SERVER_CONFIG_DIR}/master/master-config.yaml
export USE_LATEST_IMAGES=true
start_os_server

export KUBECONFIG="${ADMIN_KUBECONFIG}"

install_registry
wait_for_registry
REGISTRY_IP=$(oc get svc docker-registry -n default -o jsonpath='{.spec.clusterIP}:{.spec.ports[0].targetPort}')
# TODO REGISTRY_IP

oc login -u system:admin
oc new-project gssapiproxy
oadm policy add-scc-to-user anyuid -z default -n gssapiproxy

# create all the resources we need
cp -R test/extended/testdata/gssapi ${BASETMPDIR}
export TEST_DATA=${BASETMPDIR}/gssapi

pushd ${TEST_DATA}
    oc create -f proxy
    pushd fedora
        cp `which oc` base
        cp -R ${OS_ROOT}/hack base

        oc create -f base
        oc create -f kerberos
        oc create -f kerberos_configured
    popd
popd

export HOST='gssapiproxy-server.gssapiproxy.svc.cluster.local'
export REALM=`echo ${HOST} | tr [a-z] [A-Z]`
export BACKEND='https://openshift.default.svc.cluster.local'

# kick off a build and wait for it to finish
oc set env dc/gssapiproxy-server HOST=${HOST} REALM=${REALM} BACKEND=${BACKEND}
oc start-build --from-dir=${TEST_DATA}/proxy --follow gssapiproxy

# TODO Figure out how to set environment variables with binary builds; needed for ${REALM} and ${HOST}

pushd ${TEST_DATA}/fedora
    # oc start-build --from-dir=base --follow fedora-gssapi-base
    pushd base
        docker build --build-arg REALM=${REALM} --build-arg HOST=${HOST} -t "gssapiproxy/fedora-gssapi-base:latest" .
    popd

    # oc start-build --from-dir=kerberos --follow fedora-gssapi-kerberos
    pushd kerberos
        docker build -t "gssapiproxy/fedora-gssapi-kerberos:latest" .
    popd

    # oc start-build --from-dir=kerberos_configured --follow fedora-gssapi-kerberos-configured
    pushd kerberos_configured
        docker build -t "gssapiproxy/fedora-gssapi-kerberos-configured:latest" .
    popd
popd

SERVER_CONFIGS=(SERVER_GSSAPI_ONLY SERVER_GSSAPI_BASIC_FALLBACK)

for server_config in "${SERVER_CONFIGS[@]}"; do

    oc set env dc/gssapiproxy-server SERVER=${server_config}
    wait_for_auth_proxy ${server_config}

    oc run fedora-gssapi-base \
        --image="gssapiproxy/fedora-gssapi-base" \
        --generator=run-pod/v1 --restart=Never --attach \
        --env=SERVER=${server_config} \
        -- bash gssapi-tests.sh > "${LOG_DIR}/fedora-gssapi-base-${server_config}.log" 2>&1
    os::cmd::expect_success_and_text "cat '${LOG_DIR}/fedora-gssapi-base-${server_config}.log'" 'SUCCESS'
    os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/fedora-gssapi-base-${server_config}.log'" 'FAILURE'
    os::cmd::expect_success 'oc delete pod fedora-gssapi-base'

    oc run fedora-gssapi-base-kerberos \
        --image="gssapiproxy/fedora-gssapi-kerberos" \
        --generator=run-pod/v1 --restart=Never --attach \
        --env=SERVER=${server_config} \
        -- bash gssapi-tests.sh > "${LOG_DIR}/fedora-gssapi-base-kerberos-${server_config}.log" 2>&1
    os::cmd::expect_success_and_text "cat '${LOG_DIR}/fedora-gssapi-base-kerberos-${server_config}.log'" 'SUCCESS'
    os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/fedora-gssapi-base-kerberos-${server_config}.log'" 'FAILURE'
    os::cmd::expect_success 'oc delete pod fedora-gssapi-base-kerberos'

    oc run fedora-gssapi-base-kerberos-configured \
        --image="gssapiproxy/fedora-gssapi-kerberos-configured" \
        --generator=run-pod/v1 --restart=Never --attach \
        --env=SERVER=${server_config} \
        -- bash gssapi-tests.sh > "${LOG_DIR}/fedora-gssapi-base-kerberos-configured-${server_config}.log" 2>&1
    os::cmd::expect_success_and_text "cat '${LOG_DIR}/fedora-gssapi-base-kerberos-configured-${server_config}.log'" 'SUCCESS'
    os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/fedora-gssapi-base-kerberos-configured-${server_config}.log'" 'FAILURE'
    os::cmd::expect_success 'oc delete pod fedora-gssapi-base-kerberos-configured'

done

os::test::junit::declare_suite_end
