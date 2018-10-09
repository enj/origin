package oauthserver

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang/glog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/features"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	kclientset "k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	legacyconfigv1 "github.com/openshift/api/legacyconfig/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	osinv1 "github.com/openshift/api/osin/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	configapi "github.com/openshift/origin/pkg/cmd/server/apis/config"
	"github.com/openshift/origin/pkg/cmd/server/apis/config/latest"
	"github.com/openshift/origin/pkg/configconversion"
	"github.com/openshift/origin/pkg/oauth/urls"
	"github.com/openshift/origin/pkg/oauthserver/server/crypto"
	"github.com/openshift/origin/pkg/oauthserver/server/session"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

// TODO we need to switch the oauth server to an external type, but that can be done after we get our externally facing flag values fixed
// TODO remaining bits involve the session file, LDAP util code, validation, ...
func NewOAuthServerConfigFromInternal(oauthConfig configapi.OAuthConfig, userClientConfig *rest.Config) (*OAuthServerConfig, error) {
	buf := &bytes.Buffer{}
	internalConfig := &configapi.MasterConfig{OAuthConfig: &oauthConfig}
	if err := latest.Codec.Encode(internalConfig, buf); err != nil {
		return nil, err
	}
	legacyConfig := &legacyconfigv1.MasterConfig{}
	if _, _, err := latest.Codec.Decode(buf.Bytes(), nil, legacyConfig); err != nil {
		return nil, err
	}
	osinConfig := &osinv1.OAuthConfig{}
	if err := configconversion.Convert_legacyconfigv1_OAuthConfig_to_osinv1_OAuthConfig(legacyConfig.OAuthConfig, osinConfig, nil); err != nil {
		return nil, err
	}
	return NewOAuthServerConfig(*osinConfig, userClientConfig)
}

func NewOAuthServerConfig(oauthConfig osinv1.OAuthConfig, userClientConfig *rest.Config) (*OAuthServerConfig, error) {
	if _, ok := os.LookupEnv("MOHERE"); ok {
		cc, err := clientcmd.RESTConfigFromKubeConfig([]byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM2akNDQWRLZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFtTVNRd0lnWURWUVFEREJ0dmNHVnUKYzJocFpuUXRjMmxuYm1WeVFERTFNemt3T1RFeE16Z3dIaGNOTVRneE1EQTVNVE14T0RVM1doY05Nak14TURBNApNVE14T0RVNFdqQW1NU1F3SWdZRFZRUUREQnR2Y0dWdWMyaHBablF0YzJsbmJtVnlRREUxTXprd09URXhNemd3CmdnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM4WWdWY3laQ3pkZWF3aXNra0w1MEgKTVROMVorS2xGcGhlVjFjVTA2UEd5YU9UQzVobUwybDFNMFhoVXgvcjBDYVA4M1YzeDJ5U1h3SWhRVVNyZ25CQQpYMlBFUGZEZ0RDTzdMdXBjNTdzMDNLa0VJd2JGOXduZHdvRWpRcXhOUFBCcDRpV21TUjQ0UitLTDBZNWhRMGN1CkRSTmcyb2gvY2JQWXV2M1FUQVdLdUlQYkJmMVowN1oyLzEvM3dSWWVXcWZqTkxuZE04TnNwSExuRHFsbytEVUoKajNOWCtSNE5HRVdudjVEMnhaMnRoU2h1NVcvRWZ0NTNZTWs2Z2hvYkZNTGxrcHh1YmE1dzdhTzA4Y3duaVljRwo0aWZnR3psU0MrYjZUVllrM1FtRXdMRWNaa1NCWk5ob1JOdnNILzA2MnhOaTFXTHZuTDVQaTNqLzVPdkV2TGtICkFnTUJBQUdqSXpBaE1BNEdBMVVkRHdFQi93UUVBd0lDcERBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUEwR0NTcUcKU0liM0RRRUJDd1VBQTRJQkFRQjU4SVU4RDR1cDRkLzlmRWY0QXlEK0dxcXliZ1JTQW43ckV4OVJ1VlR4UFVkYQp1V092MUVycG1tNVJqTThLRmFYTVQ2L2tEcHhHQWJ6N2hPakF1VkhCVkpkd3MvT08zS3M0a09EK1pldE5ZZkZ6CkJzaEVyYWFpREtON1pZMXA2RzIxODI0b2pvWkNhRS9HcjlnNFpVWDJoSFR3T2lZWmhtQ2dkMjhYN3JiQW9wMWUKQzJuU2FQMk16QzZuQXgzdGowczY3eVY0V0FPODF4TmtVYnRBTllwNENITDdSWlNqcU1BR2NHZUlvVzFNM0lNeQpWYWp3ci9PQlpmQTVtTmhTSXYvV253ZHkvZGJTRldQWUZxL2NSajFCSzdkUDVhTUVqVmpZdFNiY1k2V0tpQWpaCmtTRHd3N3N1MzJ2TStiRU9naXNuRHFhV3lCdzY1Z01CMHl2NjFmQnIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://127.0.0.1:8443
  name: 10-13-129-59:8443
contexts:
- context:
    cluster: 10-13-129-59:8443
    namespace: default
    user: system:openshift-master/10-13-129-59:8443
  name: default/10-13-129-59:8443/system:openshift-master
current-context: default/10-13-129-59:8443/system:openshift-master
kind: Config
preferences: {}
users:
- name: system:openshift-master/10-13-129-59:8443
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFVENDQWZtZ0F3SUJBZ0lCQlRBTkJna3Foa2lHOXcwQkFRc0ZBREFtTVNRd0lnWURWUVFEREJ0dmNHVnUKYzJocFpuUXRjMmxuYm1WeVFERTFNemt3T1RFeE16Z3dIaGNOTVRneE1EQTVNVE14T0RVNFdoY05NakF4TURBNApNVE14T0RVNVdqQTdNUmN3RlFZRFZRUUtFdzV6ZVhOMFpXMDZiV0Z6ZEdWeWN6RWdNQjRHQTFVRUF4TVhjM2x6CmRHVnRPbTl3Wlc1emFHbG1kQzF0WVhOMFpYSXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUsKQW9JQkFRREV5MkpTZmx3Tzh0NU1WL0M0KzNhSWlpZmNKR01SQWRFNVNONGZYSHFZWkZuZVJrTWN4QzNFRDd4TQpucjEwcmJiRHMvYWFKU0FmRjRkaU4wcDhuL2l2STlhNWlQRFRFZ250a3FsRklJZFNBTzk1cXl6TmV4YjFITFoxCnpubnJBMnU3U05CMTBFenBVVXJ2Ti9uZ0NMY1gycTQvS1gyTEFhbG13UVZLZ0NsVWR3dU5ISDhBK1ViK1hjUmEKVExFbW02MDVtVzc1RDZNY3hEcFZZR3JrdWI2WU1ZZSswRk9uOTh3eVlxSzN4V1M3cmtseDJ0bE5uRFlTZXZNcwpvaFBBREVONjFHUHNlWHBpRDBpWjJVWUZGczBNVkVPVzJJYlBiZ0IwdmZyeDJQUUFJWGNvTjdWaE1JYXhkbGxSCmVXRDBIWTB0U3N1VTA3d2pMTEtFL1Jwa1hjZFJBZ01CQUFHak5UQXpNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVQKQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQWpBTUJnTlZIUk1CQWY4RUFqQUFNQTBHQ1NxR1NJYjNEUUVCQ3dVQQpBNElCQVFBVGpWQkMxemtmVFQwWWgweUIzSHFxYmJKWFhHQWI1YW9nanZJUHhEM3g1WGl5Y2tNMVV0aEFkbGZoClhicmhuWU5EenhESXpaeU5vcU5YQVA3VDE2cnI1aFM2QVM3Z3pqSWpVbVBaYkc2dFUwRmUvRWhXOHVkaXAxRkUKZ0hzZGx4ZEpDZ1Y5RjJzYzBsVDdRVFJBYU1MbzcyTlI3Uzd0SXU0dmRIeGtFRitia0RJbXdBUE8rVkFRQkxIYgpzOXhvWndSZng1QUpmdXZKSEczZCs0NHdiUlBqazl6Mko3ZS9Zc2ZVd1lJOVFmb2h3SkJncVFERllOTUhQMmhzCjIrNm1GUU1Od1VsUVFoVDZPbkVDOVMweGFOUCtEVVdRZUxYZC84WnpoN1c2S09lRGZXcmdJSklQRGIvbzlmMm8KdUR1Mld6L3hWaXREdnRRUUs4VndqNmRVNGt4NwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeE10aVVuNWNEdkxlVEZmd3VQdDJpSW9uM0NSakVRSFJPVWplSDF4Nm1HUloza1pECkhNUXR4QSs4VEo2OWRLMjJ3N1AybWlVZ0h4ZUhZamRLZkovNHJ5UFd1WWp3MHhJSjdaS3BSU0NIVWdEdmVhc3MKelhzVzlSeTJkYzU1NndOcnUwalFkZEJNNlZGSzd6ZjU0QWkzRjlxdVB5bDlpd0dwWnNFRlNvQXBWSGNMalJ4LwpBUGxHL2wzRVdreXhKcHV0T1psdStRK2pITVE2VldCcTVMbSttREdIdnRCVHAvZk1NbUtpdDhWa3U2NUpjZHJaClRadzJFbnJ6TEtJVHdBeERldFJqN0hsNllnOUltZGxHQlJiTkRGUkRsdGlHejI0QWRMMzY4ZGowQUNGM0tEZTEKWVRDR3NYWlpVWGxnOUIyTkxVckxsTk84SXl5eWhQMGFaRjNIVVFJREFRQUJBb0lCQVFDOGRqSUE0blh5OHUrawptUXMxZTh3MlVtaDkwSEwzRkpCemxhN3l4Yk82UVZBM0ozNmFDOTN3UjBtQzd2cHN4UGVrVDdJNFNKbU1iUklBCkl3YzRkbExJRjBCSmlqVm5UWDBvZ1MyTnYrc1h3MEdUZVRSOHpBWmVVbE1DV3V3eS9xR3JSNzRyTllLU1pvR20KdWlxWVBJQnJYY2RGUWN5eTFMS1Fid1ZNSlpSdkI2dHpaOS9MeGlEcm5NUnZWREdvdG8rZTk5MisrQTJtOVJDTgp5eHgxeFEwZmtVTTNzdzFiNHd3d21iWTlhcXJPbVBLeGRqSHJPSVJQYU9YRjQ0SnEzSEw5aWdoRlliZVAzbEJFCnJEZmhjWWpXTUhNbllFazR6TW5GMWNCUTN3L3QrNnE2TzhjV1J5RktPc3VUS1BlZ3psOHBMNGl6YmRrSzZ6b3QKOW9FT1BLK0pBb0dCQVBIYktsN09XTFk1ZUNNMlBQRkdHZ29iUkh3ODlaZHZYZW5OMnh0K2o5cHcyUmdJS2xSTApDcGQ0RDB4dzRXcTZ2Z0NHVGN3N3hCNVIraFpjUXdaUjZQZjdxSTE5YWM2OW80WTZiUHptTDIzV3pTOUtyZm9pCjN2NkE1cllJd1hHT2FzaHh0WmdBdDdzZmovYXBMOHp1ZkhzKzlZWmxENC8xQnF0cmJXVGZNRjhMQW9HQkFOQk4KbVhRbXNWR2N5MlRPTEhIVDNHUXc3UEVDayt1dnZPK2swUmhZdk9ZN1BhS0NHRUp3MW85Qm83QWRPNndLNUdLdwpYdU41dHpQU3dXOVZRYlVsSFNVQUNTOGVwRUxROGx6SnF4RFpmYzhOdnJYRC81cTV1OEpOZzI1SzRjZHNIRi91CjlVd3JkaWw0QmVaWFB0ODR0cDFzVFpQeVBPZjRRY3JibDRjNjFoeVRBb0dCQU1LL25DcWpOY1BtR3RzZnZZcjYKeTlUL2gvSVNsQi9ReVdxUEhMUFRBYnIveTVBU1l5TmxHYTVHT3V0dXFkVHJjanV4NmN0ZkJOajFZYy9Ia3lEdgpyQXlqVkdJNmJvelBIM0hpY2doaXdpWk1KUVREdWJ3RmdGS25NUis3aFNrUGFPVG15emNPdk9PczBwdm9PRmxvCllFeE5zaDc2R2NIdHArVTRwK25sM21scEFvR0FiSzNmLzJMa3B2RUlpWXFzVTZNMjNLdE9KQnkxTW9XWkxPc3cKRU9UVGdjZXN5Nm5Xb0d1ZzlsTkg1TzRMb1NKNXNDZlhDaFlLQ0tiUU41Y2kxakVMK0s4Qkc2MkFCRUJpQXhsUgpBRlNKT0VzeWtrRTFqZk9UeTdlSGVEYm5mNVdmWkVvWGYyczVsajlCek1EK1U1YVNhS1lGLzhlbUVWMU1ibHVOCnZvZHJDTE1DZ1lFQTN0aXlSekxCUTZ2cWpOVno4ZEVZbjBuZWU4bTJhR1I1Qm12THdlVElFdmQ1Z1NUVktxdFgKQVNQbmp2WFRRMmhITmRPdkRxVWV0UHU2ZlZKVnZVeHdENmJJd0dYeU9SMUFoOVV0NXFzY2pELzk0V3krOEdwOApHSHZpazVaT2VoNjNiUWhxd29BSmx5dm9JRTBxeUZVME91MXlSb3JCaDVGeXZjY2phd0tnbE1RPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
`))
		if err != nil {
			return nil, err
		}
		userClientConfig = cc
	}

	genericConfig := genericapiserver.NewRecommendedConfig(codecs)
	genericConfig.LoopbackClientConfig = userClientConfig

	var sessionAuth *session.Authenticator
	if oauthConfig.SessionConfig != nil {
		// TODO we really need to enforce HTTPS always
		secure := isHTTPS(oauthConfig.MasterPublicURL)
		auth, err := buildSessionAuth(secure, oauthConfig.SessionConfig)
		if err != nil {
			return nil, err
		}
		sessionAuth = auth
	}

	userClient, err := userclient.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}
	eventsClient, err := corev1.NewForConfig(userClientConfig)
	if err != nil {
		return nil, err
	}

	ret := &OAuthServerConfig{
		GenericConfig: genericConfig,
		ExtraOAuthConfig: ExtraOAuthConfig{
			Options:                        oauthConfig,
			SessionAuth:                    sessionAuth,
			EventsClient:                   eventsClient.Events(""),
			IdentityClient:                 userClient.Identities(),
			UserClient:                     userClient.Users(),
			UserIdentityMappingClient:      userClient.UserIdentityMappings(),
			OAuthAccessTokenClient:         oauthClient.OAuthAccessTokens(),
			OAuthAuthorizeTokenClient:      oauthClient.OAuthAuthorizeTokens(),
			OAuthClientClient:              oauthClient.OAuthClients(),
			OAuthClientAuthorizationClient: oauthClient.OAuthClientAuthorizations(),
		},
	}
	genericConfig.BuildHandlerChainFunc = ret.buildHandlerChainForOAuth

	return ret, nil
}

func buildSessionAuth(secure bool, config *osinv1.SessionConfig) (*session.Authenticator, error) {
	secrets, err := getSessionSecrets(config.SessionSecretsFile)
	if err != nil {
		return nil, err
	}
	sessionStore := session.NewStore(config.SessionName, secure, secrets...)
	return session.NewAuthenticator(sessionStore, time.Duration(config.SessionMaxAgeSeconds)*time.Second), nil
}

func getSessionSecrets(filename string) ([][]byte, error) {
	// Build secrets list
	var secrets [][]byte

	if len(filename) != 0 {
		sessionSecrets, err := latest.ReadSessionSecrets(filename)
		if err != nil {
			return nil, fmt.Errorf("error reading sessionSecretsFile %s: %v", filename, err)
		}

		if len(sessionSecrets.Secrets) == 0 {
			return nil, fmt.Errorf("sessionSecretsFile %s contained no secrets", filename)
		}

		for _, s := range sessionSecrets.Secrets {
			// TODO make these length independent
			secrets = append(secrets, []byte(s.Authentication))
			secrets = append(secrets, []byte(s.Encryption))
		}
	} else {
		// Generate random signing and encryption secrets if none are specified in config
		const (
			sha256KeyLenBits = sha256.BlockSize * 8 // max key size with HMAC SHA256
			aes256KeyLenBits = 256                  // max key size with AES (AES-256)
		)
		secrets = append(secrets, crypto.RandomBits(sha256KeyLenBits))
		secrets = append(secrets, crypto.RandomBits(aes256KeyLenBits))
	}

	return secrets, nil
}

// isHTTPS returns true if the given URL is a valid https URL
func isHTTPS(u string) bool {
	parsedURL, err := url.Parse(u)
	return err == nil && parsedURL.Scheme == "https"
}

type ExtraOAuthConfig struct {
	Options osinv1.OAuthConfig

	// AssetPublicAddresses contains valid redirectURI prefixes to direct browsers to the web console
	AssetPublicAddresses []string

	// KubeClient is kubeclient with enough permission for the auth API
	KubeClient kclientset.Interface

	// EventsClient is for creating user events
	EventsClient corev1.EventInterface

	// RouteClient provides a client for OpenShift routes API.
	RouteClient routeclient.RouteV1Interface

	UserClient                userclient.UserInterface
	IdentityClient            userclient.IdentityInterface
	UserIdentityMappingClient userclient.UserIdentityMappingInterface

	OAuthAccessTokenClient         oauthclient.OAuthAccessTokenInterface
	OAuthAuthorizeTokenClient      oauthclient.OAuthAuthorizeTokenInterface
	OAuthClientClient              oauthclient.OAuthClientInterface
	OAuthClientAuthorizationClient oauthclient.OAuthClientAuthorizationInterface

	SessionAuth *session.Authenticator
}

func (c *ExtraOAuthConfig) Complete() *ExtraOAuthConfig {
	scheme := runtime.NewScheme()
	utilruntime.Must(osinv1.Install(scheme))
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDecoder(osinv1.GroupVersion)

	for i, idp := range c.Options.IdentityProviders {
		var fatal error
		c.Options.IdentityProviders[i].Provider.Object, fatal = runtime.Decode(decoder, idp.Provider.Raw)
		utilruntime.Must(fatal)
		glog.Error(string(idp.Provider.Raw))
		glog.Errorf("%#v", c.Options.IdentityProviders[i].Provider.Object)
	}

	return c
}

type OAuthServerConfig struct {
	GenericConfig    *genericapiserver.RecommendedConfig
	ExtraOAuthConfig ExtraOAuthConfig
}

// OAuthServer serves non-API endpoints for openshift.
type OAuthServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer

	PublicURL url.URL
}

type completedOAuthConfig struct {
	GenericConfig    genericapiserver.CompletedConfig
	ExtraOAuthConfig *ExtraOAuthConfig
}

type CompletedOAuthConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedOAuthConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *OAuthServerConfig) Complete() completedOAuthConfig {
	cfg := completedOAuthConfig{
		c.GenericConfig.Complete(),
		c.ExtraOAuthConfig.Complete(),
	}

	return cfg
}

// this server is odd.  It doesn't delegate.  We mostly leave it alone, so I don't plan to make it look "normal".  We'll
// model it as a separate API server to reason about its handling chain, but otherwise, just let it be
func (c completedOAuthConfig) New(delegationTarget genericapiserver.DelegationTarget) (*OAuthServer, error) {
	genericServer, err := c.GenericConfig.New("openshift-oauth", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &OAuthServer{
		GenericAPIServer: genericServer,
	}

	return s, nil
}

func (c *OAuthServerConfig) buildHandlerChainForOAuth(startingHandler http.Handler, genericConfig *genericapiserver.Config) http.Handler {
	handler, err := c.WithOAuth(startingHandler)
	if err != nil {
		// the existing errors all cause the server to die anyway
		panic(err)
	}
	if utilfeature.DefaultFeatureGate.Enabled(features.AdvancedAuditing) {
		handler = genericapifilters.WithAudit(handler, genericConfig.AuditBackend, genericConfig.AuditPolicyChecker, genericConfig.LongRunningFunc)
	}

	handler = genericfilters.WithMaxInFlightLimit(handler, genericConfig.MaxRequestsInFlight, genericConfig.MaxMutatingRequestsInFlight, genericConfig.LongRunningFunc)
	handler = genericfilters.WithCORS(handler, genericConfig.CorsAllowedOriginList, nil, nil, nil, "true")
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, genericConfig.LongRunningFunc, genericConfig.RequestTimeout)
	handler = genericapifilters.WithRequestInfo(handler, genericapiserver.NewRequestInfoResolver(genericConfig))
	handler = genericfilters.WithPanicRecovery(handler)
	return handler
}

// TODO, this moves to the `apiserver.go` when we have it for this group
// TODO TODO, this actually looks a lot like a controller or an add-on manager style thing.  Seems like we'd want to do this outside
// EnsureBootstrapOAuthClients creates or updates the bootstrap oauth clients that openshift relies upon.
func (c *OAuthServerConfig) StartOAuthClientsBootstrapping(context genericapiserver.PostStartHookContext) error {
	// the TODO above still applies, but this makes it possible for this poststarthook to do its job with a split kubeapiserver and not run forever
	go func() {
		// error is guaranteed to be nil
		_ = wait.PollUntil(1*time.Second, func() (done bool, err error) {
			webConsoleClient := oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: openShiftWebConsoleClientID},
				Secret:                "",
				RespondWithChallenges: false,
				RedirectURIs:          c.ExtraOAuthConfig.AssetPublicAddresses,
				GrantMethod:           oauthv1.GrantHandlerAuto,
			}
			if err := ensureOAuthClient(webConsoleClient, c.ExtraOAuthConfig.OAuthClientClient, true, false); err != nil {
				utilruntime.HandleError(err)
				return false, nil
			}

			browserClient := oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: openShiftBrowserClientID},
				Secret:                crypto.Random256BitsString(),
				RespondWithChallenges: false,
				RedirectURIs:          []string{urls.OpenShiftOAuthTokenDisplayURL(c.ExtraOAuthConfig.Options.MasterPublicURL)},
				GrantMethod:           oauthv1.GrantHandlerAuto,
			}
			if err := ensureOAuthClient(browserClient, c.ExtraOAuthConfig.OAuthClientClient, true, true); err != nil {
				utilruntime.HandleError(err)
				return false, nil
			}

			cliClient := oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: openShiftCLIClientID},
				Secret:                "",
				RespondWithChallenges: true,
				RedirectURIs:          []string{urls.OpenShiftOAuthTokenImplicitURL(c.ExtraOAuthConfig.Options.MasterPublicURL)},
				GrantMethod:           oauthv1.GrantHandlerAuto,
			}
			if err := ensureOAuthClient(cliClient, c.ExtraOAuthConfig.OAuthClientClient, false, false); err != nil {
				utilruntime.HandleError(err)
				return false, nil
			}

			return true, nil
		}, context.StopCh)
	}()

	return nil
}
