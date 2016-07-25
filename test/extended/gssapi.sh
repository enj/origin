#!/bin/bash
#
# Extended tests for logging in using GSSAPI

set -o errexit
set -o nounset
set -o pipefail

OS_ROOT="$(dirname "${BASH_SOURCE}")/../.."
cd "${OS_ROOT}"
source hack/lib/init.sh

os::log::stacktrace::install
os::test::junit::declare_suite_start "test-extended/gssapiproxy"
os::util::environment::setup_time_vars
os::build::setup_env

hack/build-go.sh cmd/oc -tags=gssapi
os::cmd::expect_success_and_text 'oc version' 'GSSAPI Kerberos SPNEGO'

function cleanup() {
    out=$?
    os::test::junit::reconcile_output
    cleanup_openshift
    echo "[INFO] Exiting"
    [[ -n "${SKIP_TEARDOWN-}" ]] && oc project gssapiproxy ##TODO remove
    return $out
}

function wait_for_auth_proxy() {
    local server_config="${1}"
    local spec='{.items[0].spec.containers[0].env[?(@.name=="SERVER")].value}_{.items[0].status.conditions[?(@.type=="Ready")].status}'
    os::cmd::try_until_text "oc get pods -l deploymentconfig=gssapiproxy-server -o jsonpath='${spec}'" "^${server_config}_True$"
}

trap "cleanup" EXIT

echo "[INFO] Starting server"

ensure_iptables_or_die ## Is this needed?
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
REALM="$(echo ${HOST} | tr [[:lower:]] [[:upper:]])"
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

        oc run "${os_image}-gssapi-base" \
            --image="gssapiproxy/${os_image}-gssapi-base" \
            --generator=run-pod/v1 --restart=Never --attach \
            --env=SERVER="${server_config}" \
            -- bash gssapi-tests.sh > "${LOG_DIR}/${os_image}-gssapi-base-${server_config}.log" 2>&1
        os::cmd::expect_success_and_text "cat '${LOG_DIR}/${os_image}-gssapi-base-${server_config}.log'" 'SUCCESS'
        os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/${os_image}-gssapi-base-${server_config}.log'" 'FAILURE'
        os::cmd::expect_success "oc delete pod ${os_image}-gssapi-base"

        oc run "${os_image}-gssapi-kerberos" \
            --image="gssapiproxy/${os_image}-gssapi-kerberos" \
            --generator=run-pod/v1 --restart=Never --attach \
            --env=SERVER="${server_config}" \
            -- bash gssapi-tests.sh > "${LOG_DIR}/${os_image}-gssapi-kerberos-${server_config}.log" 2>&1
        os::cmd::expect_success_and_text "cat '${LOG_DIR}/${os_image}-gssapi-kerberos-${server_config}.log'" 'SUCCESS'
        os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/${os_image}-gssapi-kerberos-${server_config}.log'" 'FAILURE'
        os::cmd::expect_success "oc delete pod ${os_image}-gssapi-kerberos"

        oc run "${os_image}-gssapi-kerberos-configured" \
            --image="gssapiproxy/${os_image}-gssapi-kerberos-configured" \
            --generator=run-pod/v1 --restart=Never --attach \
            --env=SERVER="${server_config}" \
            -- bash gssapi-tests.sh > "${LOG_DIR}/${os_image}-gssapi-kerberos-configured-${server_config}.log" 2>&1
        os::cmd::expect_success_and_text "cat '${LOG_DIR}/${os_image}-gssapi-kerberos-configured-${server_config}.log'" 'SUCCESS'
        os::cmd::expect_success_and_not_text "cat '${LOG_DIR}/${os_image}-gssapi-kerberos-configured-${server_config}.log'" 'FAILURE'
        os::cmd::expect_success "oc delete pod ${os_image}-gssapi-kerberos-configured"

    done

done

os::test::junit::declare_suite_end
