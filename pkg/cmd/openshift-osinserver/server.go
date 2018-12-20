package openshift_osinserver

import (
	"errors"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/rest"

	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/origin/pkg/oauthserver/oauthserver"

	// for metrics
	_ "k8s.io/kubernetes/pkg/client/metrics/prometheus"
)

func RunOpenShiftOsinServer(oauthConfig *osinv1.OAuthConfig, kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	if oauthConfig == nil {
		return errors.New("osin server requires non-empty oauthConfig")
	}

	oauthServerConfig, err := oauthserver.NewOAuthServerConfig(*oauthConfig, kubeClientConfig)
	if err != nil {
		return err
	}

	// TODO you probably want to set this
	//oauthServerConfig.GenericConfig.CorsAllowedOriginList = genericConfig.CorsAllowedOriginList
	//oauthServerConfig.GenericConfig.SecureServing = genericConfig.SecureServing
	//oauthServerConfig.GenericConfig.AuditBackend = genericConfig.AuditBackend
	//oauthServerConfig.GenericConfig.AuditPolicyChecker = genericConfig.AuditPolicyChecker

	// Build the list of valid redirect_uri prefixes for a login using the openshift-web-console client to redirect to
	oauthServerConfig.ExtraOAuthConfig.AssetPublicAddresses = []string{oauthConfig.AssetPublicURL}

	oauthServer, err := oauthServerConfig.Complete().New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	return oauthServer.GenericAPIServer.PrepareRun().Run(stopCh)

}
