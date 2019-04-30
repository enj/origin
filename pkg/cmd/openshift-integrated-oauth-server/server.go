package openshift_integrated_oauth_server

import (
	"errors"

	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/library-go/pkg/config/helpers"
	"github.com/openshift/origin/pkg/cmd/openshift-apiserver/openshiftapiserver/configprocessing"
	"github.com/openshift/origin/pkg/oauthserver/oauthserver"

	// for metrics
	_ "k8s.io/kubernetes/pkg/client/metrics/prometheus"
)

func RunOsinServer(osinConfig *osinv1.OsinServerConfig, stopCh <-chan struct{}) error {
	if osinConfig == nil {
		return errors.New("osin server requires non-empty oauthConfig")
	}

	oauthServerConfig, err := newOAuthServerConfig(osinConfig)
	if err != nil {
		return err
	}

	oauthServer, err := oauthServerConfig.Complete().New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	oauthServer.GenericAPIServer.AddPostStartHookOrDie("oauth.openshift.io-startoauthclientsbootstrapping", oauthServerConfig.StartOAuthClientsBootstrapping)

	return oauthServer.GenericAPIServer.PrepareRun().Run(stopCh)
}

func newOAuthServerConfig(osinConfig *osinv1.OsinServerConfig) (*oauthserver.OAuthServerConfig, error) {
	genericConfig := genericapiserver.NewRecommendedConfig(legacyscheme.Codecs)

	servingOptions, err := configprocessing.ToServingOptions(osinConfig.ServingInfo)
	if err != nil {
		return nil, err
	}
	if err := servingOptions.ApplyTo(&genericConfig.Config.SecureServing, &genericConfig.Config.LoopbackClientConfig); err != nil {
		return nil, err
	}
	// the oauth-server must only run in http1 to avoid http2 connection re-use problems when improperly re-using a wildcard certificate
	genericConfig.Config.SecureServing.HTTP1Only = true

	authenticationOptions := genericapiserveroptions.NewDelegatingAuthenticationOptions()
	authenticationOptions.ClientCert.ClientCA = osinConfig.ServingInfo.ClientCA
	authenticationOptions.RemoteKubeConfigFile = osinConfig.KubeClientConfig.KubeConfig
	if err := authenticationOptions.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.OpenAPIConfig); err != nil {
		return nil, err
	}

	authorizationOptions := genericapiserveroptions.NewDelegatingAuthorizationOptions().
		// TODO better formalize / generate this list as trailing slashes matter
		// The five sections are:
		// 1. Health checks
		// 2. OAuth
		// 3. Login
		// 4. Logout
		// 5. OAuth callbacks
		WithAlwaysAllowPaths("/healthz", "/healthz/", "/oauth/", "/login", "/login/", "/logout", "/oauth2callback/").
		WithAlwaysAllowGroups("system:masters")
	authorizationOptions.RemoteKubeConfigFile = osinConfig.KubeClientConfig.KubeConfig
	if err := authorizationOptions.ApplyTo(&genericConfig.Authorization); err != nil {
		return nil, err
	}

	// TODO You need real overrides for rate limiting
	kubeClientConfig, err := helpers.GetKubeConfigOrInClusterConfig(osinConfig.KubeClientConfig.KubeConfig, osinConfig.KubeClientConfig.ConnectionOverrides)
	if err != nil {
		return nil, err
	}

	oauthServerConfig, err := oauthserver.NewOAuthServerConfig(osinConfig.OAuthConfig, kubeClientConfig, genericConfig)
	if err != nil {
		return nil, err
	}

	// TODO you probably want to set this
	oauthServerConfig.GenericConfig.CorsAllowedOriginList = osinConfig.CORSAllowedOrigins
	//oauthServerConfig.GenericConfig.AuditBackend = genericConfig.AuditBackend
	//oauthServerConfig.GenericConfig.AuditPolicyChecker = genericConfig.AuditPolicyChecker

	return oauthServerConfig, nil
}
