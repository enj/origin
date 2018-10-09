package openshiftkubeapiserver

import (
	"fmt"
	"os"
	"time"

	"k8s.io/apiserver/pkg/admission"
	admissionmetrics "k8s.io/apiserver/pkg/admission/metrics"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/options"
	clientgoinformers "k8s.io/client-go/informers"
	kexternalinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	internalinformers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	kinternalinformers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	"k8s.io/kubernetes/pkg/master"
	"k8s.io/kubernetes/pkg/quota/generic"
	"k8s.io/kubernetes/pkg/quota/install"

	kubecontrolplanev1 "github.com/openshift/api/kubecontrolplane/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	"github.com/openshift/origin/pkg/admission/namespaceconditions"
	originadmission "github.com/openshift/origin/pkg/apiserver/admission"
	"github.com/openshift/origin/pkg/cmd/openshift-apiserver/openshiftapiserver"
	"github.com/openshift/origin/pkg/cmd/openshift-apiserver/openshiftapiserver/configprocessing"
	oadmission "github.com/openshift/origin/pkg/cmd/server/admission"
	"github.com/openshift/origin/pkg/image/apiserver/registryhostname"
	imageinformer "github.com/openshift/origin/pkg/image/generated/informers/internalversion"
	imageclient "github.com/openshift/origin/pkg/image/generated/internalclientset"
	quotainformer "github.com/openshift/origin/pkg/quota/generated/informers/internalversion"
	quotaclient "github.com/openshift/origin/pkg/quota/generated/internalclientset"
	securityinformer "github.com/openshift/origin/pkg/security/generated/informers/internalversion"
	securityclient "github.com/openshift/origin/pkg/security/generated/internalclientset"
	usercache "github.com/openshift/origin/pkg/user/cache"
)

type KubeAPIServerServerPatchContext struct {
	initialized bool

	postStartHooks     map[string]genericapiserver.PostStartHookFunc
	informerStartFuncs []func(stopCh <-chan struct{})
}

func NewOpenShiftKubeAPIServerConfigPatch(delegateAPIServer genericapiserver.DelegationTarget, kubeAPIServerConfig *kubecontrolplanev1.KubeAPIServerConfig) (app.KubeAPIServerConfigFunc, *KubeAPIServerServerPatchContext) {
	patchContext := &KubeAPIServerServerPatchContext{
		postStartHooks: map[string]genericapiserver.PostStartHookFunc{},
	}
	return func(genericConfig *genericapiserver.Config, internalInformers internalinformers.SharedInformerFactory, kubeInformers clientgoinformers.SharedInformerFactory, pluginInitializers *[]admission.PluginInitializer) (genericapiserver.DelegationTarget, error) {

		loop := genericConfig.LoopbackClientConfig

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
			loop = cc
		}

		kubeAPIServerInformers, err := NewInformers(internalInformers, kubeInformers, loop)
		if err != nil {
			return nil, err
		}

		// AUTHENTICATOR
		authenticator, postStartHooks, err := NewAuthenticator(
			kubeAPIServerConfig.ServingInfo.ServingInfo,
			kubeAPIServerConfig.ServiceAccountPublicKeyFiles, kubeAPIServerConfig.OAuthConfig, kubeAPIServerConfig.AuthConfig,
			loop,
			kubeAPIServerInformers.OpenshiftOAuthInformers.Oauth().V1().OAuthClients().Lister(),
			kubeAPIServerInformers.OpenshiftUserInformers.User().V1().Groups())
		if err != nil {
			return nil, err
		}
		genericConfig.Authentication.Authenticator = authenticator
		for key, fn := range postStartHooks {
			patchContext.postStartHooks[key] = fn
		}
		// END AUTHENTICATOR

		// AUTHORIZER
		genericConfig.RequestInfoResolver = configprocessing.OpenshiftRequestInfoResolver()
		authorizer := NewAuthorizer(internalInformers, kubeInformers)
		genericConfig.Authorization.Authorizer = authorizer
		// END AUTHORIZER

		// ADMISSION
		projectCache, err := openshiftapiserver.NewProjectCache(kubeAPIServerInformers.InternalKubernetesInformers.Core().InternalVersion().Namespaces(), genericConfig.LoopbackClientConfig, kubeAPIServerConfig.ProjectConfig.DefaultNodeSelector)
		if err != nil {
			return nil, err
		}
		clusterQuotaMappingController := openshiftapiserver.NewClusterQuotaMappingController(kubeAPIServerInformers.InternalKubernetesInformers.Core().InternalVersion().Namespaces(), kubeAPIServerInformers.InternalOpenshiftQuotaInformers.Quota().InternalVersion().ClusterResourceQuotas())
		patchContext.postStartHooks["quota.openshift.io-clusterquotamapping"] = func(context genericapiserver.PostStartHookContext) error {
			go clusterQuotaMappingController.Run(5, context.StopCh)
			return nil
		}
		kubeClient, err := kubernetes.NewForConfig(genericConfig.LoopbackClientConfig)
		if err != nil {
			return nil, err
		}
		registryHostnameRetriever, err := registryhostname.DefaultRegistryHostnameRetriever(genericConfig.LoopbackClientConfig, kubeAPIServerConfig.ImagePolicyConfig.ExternalRegistryHostname, kubeAPIServerConfig.ImagePolicyConfig.InternalRegistryHostname)
		if err != nil {
			return nil, err
		}
		// TODO make a union registry
		quotaRegistry := generic.NewRegistry(install.NewQuotaConfigurationForAdmission().Evaluators())
		openshiftPluginInitializer := &oadmission.PluginInitializer{
			ProjectCache:                 projectCache,
			OriginQuotaRegistry:          quotaRegistry,
			RESTClientConfig:             *genericConfig.LoopbackClientConfig,
			ClusterResourceQuotaInformer: kubeAPIServerInformers.GetInternalOpenshiftQuotaInformers().Quota().InternalVersion().ClusterResourceQuotas(),
			ClusterQuotaMapper:           clusterQuotaMappingController.GetClusterQuotaMapper(),
			RegistryHostnameRetriever:    registryHostnameRetriever,
			SecurityInformers:            kubeAPIServerInformers.GetInternalOpenshiftSecurityInformers(),
			UserInformers:                kubeAPIServerInformers.GetOpenshiftUserInformers(),
		}
		*pluginInitializers = append(*pluginInitializers, openshiftPluginInitializer)

		// set up the decorators we need
		namespaceLabelDecorator := namespaceconditions.NamespaceLabelConditions{
			NamespaceClient: kubeClient.CoreV1(),
			NamespaceLister: kubeInformers.Core().V1().Namespaces().Lister(),

			SkipLevelZeroNames: originadmission.SkipRunLevelZeroPlugins,
			SkipLevelOneNames:  originadmission.SkipRunLevelOnePlugins,
		}
		options.AdmissionDecorator = admission.Decorators{
			admission.DecoratorFunc(namespaceLabelDecorator.WithNamespaceLabelConditions),
			admission.DecoratorFunc(admissionmetrics.WithControllerMetrics),
		}
		// END ADMISSION

		// HANDLER CHAIN (with oauth server and web console)
		genericConfig.BuildHandlerChainFunc, postStartHooks, err = BuildHandlerChain(genericConfig, kubeAPIServerConfig.OAuthConfig, kubeAPIServerConfig.UserAgentMatchingConfig, kubeAPIServerConfig.ConsolePublicURL)
		if err != nil {
			return nil, err
		}
		for key, fn := range postStartHooks {
			patchContext.postStartHooks[key] = fn
		}
		// END HANDLER CHAIN

		// CONSTRUCT DELEGATE
		nonAPIServerConfig, err := NewOpenshiftNonAPIConfig(genericConfig, kubeInformers, kubeAPIServerConfig.OAuthConfig, kubeAPIServerConfig.AuthConfig)
		if err != nil {
			return nil, err
		}
		openshiftNonAPIServer, err := nonAPIServerConfig.Complete().New(delegateAPIServer)
		if err != nil {
			return nil, err
		}
		// END CONSTRUCT DELEGATE

		patchContext.informerStartFuncs = append(patchContext.informerStartFuncs, kubeAPIServerInformers.Start)
		patchContext.initialized = true

		return openshiftNonAPIServer.GenericAPIServer, nil
	}, patchContext
}

func (c *KubeAPIServerServerPatchContext) PatchServer(server *master.Master) error {
	if !c.initialized {
		return fmt.Errorf("not initialized with config")
	}

	for name, fn := range c.postStartHooks {
		server.GenericAPIServer.AddPostStartHookOrDie(name, fn)
	}
	server.GenericAPIServer.AddPostStartHookOrDie("openshift.io-startkubeinformers", func(context genericapiserver.PostStartHookContext) error {
		for _, fn := range c.informerStartFuncs {
			fn(context.StopCh)
		}
		return nil
	})

	return nil
}

// NewInformers is only exposed for the build's integration testing until it can be fixed more appropriately.
func NewInformers(internalInformers internalinformers.SharedInformerFactory, versionedInformers clientgoinformers.SharedInformerFactory, loopbackClientConfig *rest.Config) (*KubeAPIServerInformers, error) {
	imageClient, err := imageclient.NewForConfig(loopbackClientConfig)
	if err != nil {
		return nil, err
	}
	oauthClient, err := oauthclient.NewForConfig(loopbackClientConfig)
	if err != nil {
		return nil, err
	}
	quotaClient, err := quotaclient.NewForConfig(loopbackClientConfig)
	if err != nil {
		return nil, err
	}
	securityClient, err := securityclient.NewForConfig(loopbackClientConfig)
	if err != nil {
		return nil, err
	}
	userClient, err := userclient.NewForConfig(loopbackClientConfig)
	if err != nil {
		return nil, err
	}

	// TODO find a single place to create and start informers.  During the 1.7 rebase this will come more naturally in a config object,
	// before then we should try to eliminate our direct to storage access.  It's making us do weird things.
	const defaultInformerResyncPeriod = 10 * time.Minute

	ret := &KubeAPIServerInformers{
		InternalKubernetesInformers:        internalInformers,
		KubernetesInformers:                versionedInformers,
		InternalOpenshiftImageInformers:    imageinformer.NewSharedInformerFactory(imageClient, defaultInformerResyncPeriod),
		OpenshiftOAuthInformers:            oauthinformer.NewSharedInformerFactory(oauthClient, defaultInformerResyncPeriod),
		InternalOpenshiftQuotaInformers:    quotainformer.NewSharedInformerFactory(quotaClient, defaultInformerResyncPeriod),
		InternalOpenshiftSecurityInformers: securityinformer.NewSharedInformerFactory(securityClient, defaultInformerResyncPeriod),
		OpenshiftUserInformers:             userinformer.NewSharedInformerFactory(userClient, defaultInformerResyncPeriod),
	}
	if err := ret.OpenshiftUserInformers.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
		usercache.ByUserIndexName: usercache.ByUserIndexKeys,
	}); err != nil {
		return nil, err
	}

	return ret, nil
}

type KubeAPIServerInformers struct {
	InternalKubernetesInformers        kinternalinformers.SharedInformerFactory
	KubernetesInformers                kexternalinformers.SharedInformerFactory
	OpenshiftOAuthInformers            oauthinformer.SharedInformerFactory
	InternalOpenshiftImageInformers    imageinformer.SharedInformerFactory
	InternalOpenshiftQuotaInformers    quotainformer.SharedInformerFactory
	InternalOpenshiftSecurityInformers securityinformer.SharedInformerFactory
	OpenshiftUserInformers             userinformer.SharedInformerFactory
}

func (i *KubeAPIServerInformers) GetInternalKubernetesInformers() kinternalinformers.SharedInformerFactory {
	return i.InternalKubernetesInformers
}
func (i *KubeAPIServerInformers) GetKubernetesInformers() kexternalinformers.SharedInformerFactory {
	return i.KubernetesInformers
}
func (i *KubeAPIServerInformers) GetInternalOpenshiftImageInformers() imageinformer.SharedInformerFactory {
	return i.InternalOpenshiftImageInformers
}
func (i *KubeAPIServerInformers) GetInternalOpenshiftQuotaInformers() quotainformer.SharedInformerFactory {
	return i.InternalOpenshiftQuotaInformers
}
func (i *KubeAPIServerInformers) GetInternalOpenshiftSecurityInformers() securityinformer.SharedInformerFactory {
	return i.InternalOpenshiftSecurityInformers
}
func (i *KubeAPIServerInformers) GetOpenshiftUserInformers() userinformer.SharedInformerFactory {
	return i.OpenshiftUserInformers
}

func (i *KubeAPIServerInformers) Start(stopCh <-chan struct{}) {
	i.InternalKubernetesInformers.Start(stopCh)
	i.KubernetesInformers.Start(stopCh)
	i.OpenshiftOAuthInformers.Start(stopCh)
	i.InternalOpenshiftImageInformers.Start(stopCh)
	i.InternalOpenshiftQuotaInformers.Start(stopCh)
	i.InternalOpenshiftSecurityInformers.Start(stopCh)
	i.OpenshiftUserInformers.Start(stopCh)
}
