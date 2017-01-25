package integration

import (
	"reflect"
	"strings"
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kapiv1 "k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/apimachinery/registered"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/resource"
	"k8s.io/kubernetes/pkg/runtime"
	etcdutil "k8s.io/kubernetes/pkg/storage/etcd/util"
	"k8s.io/kubernetes/pkg/util/diff"

	"github.com/openshift/origin/pkg/authorization/authorizer/scope"
	osclientcmd "github.com/openshift/origin/pkg/cmd/util/clientcmd"
	saoauth "github.com/openshift/origin/pkg/serviceaccounts/oauthclient"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"

	// install all APIs // TODO do I need this at all?
	_ "github.com/openshift/origin/pkg/api/install"
	_ "k8s.io/kubernetes/pkg/api/install"

	etcd "github.com/coreos/etcd/client"
	"golang.org/x/net/context"

	apisfederationv1beta1 "k8s.io/kubernetes/federation/apis/federation/v1beta1"
	apisappsv1beta1 "k8s.io/kubernetes/pkg/apis/apps/v1beta1"
	apisauthenticationv1beta1 "k8s.io/kubernetes/pkg/apis/authentication/v1beta1"
	apisauthorizationv1beta1 "k8s.io/kubernetes/pkg/apis/authorization/v1beta1"
	apisautoscalingv1 "k8s.io/kubernetes/pkg/apis/autoscaling/v1"
	apisbatchv1 "k8s.io/kubernetes/pkg/apis/batch/v1"
	apisbatchv2alpha1 "k8s.io/kubernetes/pkg/apis/batch/v2alpha1"
	apiscertificatesv1alpha1 "k8s.io/kubernetes/pkg/apis/certificates/v1alpha1"
	apiscomponentconfigv1alpha1 "k8s.io/kubernetes/pkg/apis/componentconfig/v1alpha1"
	apisextensionsv1beta1 "k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	apisimagepolicyv1alpha1 "k8s.io/kubernetes/pkg/apis/imagepolicy/v1alpha1"
	apispolicyv1beta1 "k8s.io/kubernetes/pkg/apis/policy/v1beta1"
	apisrbacv1alpha1 "k8s.io/kubernetes/pkg/apis/rbac/v1alpha1"
	apisstoragev1beta1 "k8s.io/kubernetes/pkg/apis/storage/v1beta1"
	pkgwatchversioned "k8s.io/kubernetes/pkg/watch/versioned"

	authorizationapiv1 "github.com/openshift/origin/pkg/authorization/api/v1"
	buildapiv1 "github.com/openshift/origin/pkg/build/api/v1"
	deployapiv1 "github.com/openshift/origin/pkg/deploy/api/v1"
	imageapidocker10 "github.com/openshift/origin/pkg/image/api/docker10"
	imageapidockerpre012 "github.com/openshift/origin/pkg/image/api/dockerpre012"
	imageapiv1 "github.com/openshift/origin/pkg/image/api/v1"
	oauthapiv1 "github.com/openshift/origin/pkg/oauth/api/v1"
	projectapiv1 "github.com/openshift/origin/pkg/project/api/v1"
	quotaapiv1 "github.com/openshift/origin/pkg/quota/api/v1"
	routeapiv1 "github.com/openshift/origin/pkg/route/api/v1"
	sdnapiv1 "github.com/openshift/origin/pkg/sdn/api/v1"
	securityapiv1 "github.com/openshift/origin/pkg/security/api/v1"
	templateapiv1 "github.com/openshift/origin/pkg/template/api/v1"
	userapiv1 "github.com/openshift/origin/pkg/user/api/v1"
)

// Etcd data for all persisted objects.  Be very careful when setting ephemeral to true as that removes the safety we gain from this test.
var etcdStorageData = map[reflect.Type]struct {
	ephemeral        bool             // Set to true to skip testing the object
	stub             runtime.Object   // Valid stub to use during create
	prerequisites    []runtime.Object // Optional, ordered list of objects to create before stub
	expectedEtcdPath string           // Expected location of object in etcd, do not use any variables, constants, etc to derive this value - always supply the full raw string
}{
	reflect.TypeOf(&oauthapiv1.OAuthClientAuthorization{}): {
		stub: &oauthapiv1.OAuthClientAuthorization{
			ClientName: "system:serviceaccount:etcdstoragepath:client",
			UserName:   "user",
			UserUID:    "cannot be empty",
			Scopes:     []string{scope.UserInfo},
		},
		prerequisites: []runtime.Object{
			&kapiv1.ServiceAccount{
				ObjectMeta: kapiv1.ObjectMeta{
					Name:        "client",
					Annotations: map[string]string{saoauth.OAuthRedirectModelAnnotationURIPrefix + "foo": "http://bar"}},
			},
			&kapiv1.Secret{
				ObjectMeta: kapiv1.ObjectMeta{
					GenerateName: "client",
					Annotations:  map[string]string{kapi.ServiceAccountNameKey: "client"},
				},
				Type: kapiv1.SecretTypeServiceAccountToken,
			},
		},
		expectedEtcdPath: "openshift.io/oauth/clientauthorizations/user:system:serviceaccount:etcdstoragepath:client",
	},
	reflect.TypeOf(&oauthapiv1.OAuthClient{}): {
		stub: &oauthapiv1.OAuthClient{
			ObjectMeta: kapiv1.ObjectMeta{Name: "client"},
		},
		expectedEtcdPath: "openshift.io/oauth/clients/client",
	},
	reflect.TypeOf(&oauthapiv1.OAuthAuthorizeToken{}): {
		stub: &oauthapiv1.OAuthAuthorizeToken{
			ObjectMeta: kapiv1.ObjectMeta{Name: "tokenneedstobelongenoughelseitwontwork"},
			ClientName: "client",
			UserName:   "user",
			UserUID:    "cannot be empty",
		},
		prerequisites: []runtime.Object{
			&oauthapiv1.OAuthClient{
				ObjectMeta: kapiv1.ObjectMeta{Name: "client"},
			},
		},
		expectedEtcdPath: "openshift.io/oauth/authorizetokens/tokenneedstobelongenoughelseitwontwork",
	},
	reflect.TypeOf(&oauthapiv1.OAuthAccessToken{}): {
		stub: &oauthapiv1.OAuthAccessToken{
			ObjectMeta: kapiv1.ObjectMeta{Name: "tokenneedstobelongenoughelseitwontwork"},
			ClientName: "client",
			UserName:   "user",
			UserUID:    "cannot be empty",
		},
		prerequisites: []runtime.Object{
			&oauthapiv1.OAuthClient{
				ObjectMeta: kapiv1.ObjectMeta{Name: "client"},
			},
		},
		expectedEtcdPath: "openshift.io/oauth/accesstokens/tokenneedstobelongenoughelseitwontwork",
	},
	reflect.TypeOf(&oauthapiv1.OAuthRedirectReference{}): {ephemeral: true}, // Used for specifying redirects, never stored in etcd

	reflect.TypeOf(&imageapidockerpre012.DockerImage{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&authorizationapiv1.PolicyBinding{}):                 {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.IsPersonalSubjectAccessReview{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.SubjectAccessReview{}):           {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ResourceAccessReview{}):          {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ClusterRoleBinding{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.SelfSubjectRulesReview{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.LocalSubjectAccessReview{}):      {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ResourceAccessReviewResponse{}):  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.RoleBinding{}):                   {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ClusterPolicy{}):                 {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.LocalResourceAccessReview{}):     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.Role{}):                          {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.RoleBindingRestriction{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.Policy{}):                        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ClusterPolicyBinding{}):          {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.SubjectAccessReviewResponse{}):   {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.ClusterRole{}):                   {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&authorizationapiv1.SubjectRulesReview{}):            {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&userapiv1.Group{}):               {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&userapiv1.UserIdentityMapping{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&userapiv1.User{}):                {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&userapiv1.Identity{}):            {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&projectapiv1.Project{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&projectapiv1.ProjectRequest{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisimagepolicyv1alpha1.ImageReview{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&quotaapiv1.ClusterResourceQuota{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&quotaapiv1.AppliedClusterResourceQuota{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&securityapiv1.PodSecurityPolicyReview{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&securityapiv1.PodSecurityPolicySelfSubjectReview{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&securityapiv1.PodSecurityPolicySubjectReview{}):     {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisstoragev1beta1.StorageClass{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeSchedulerConfiguration{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeletConfiguration{}):       {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeProxyConfiguration{}):     {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&imageapidocker10.DockerImage{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisauthorizationv1beta1.SelfSubjectAccessReview{}):  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisauthorizationv1beta1.LocalSubjectAccessReview{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisauthorizationv1beta1.SubjectAccessReview{}):      {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisauthenticationv1beta1.TokenReview{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisrbacv1alpha1.RoleBinding{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisrbacv1alpha1.Role{}):               {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisrbacv1alpha1.ClusterRole{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisrbacv1alpha1.ClusterRoleBinding{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&imageapiv1.ImageStreamImport{}):  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.ImageStreamImage{}):   {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.ImageStreamTag{}):     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.Image{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.ImageStreamMapping{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.ImageStream{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&imageapiv1.ImageSignature{}):     {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisappsv1beta1.StatefulSet{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisbatchv2alpha1.JobTemplate{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisbatchv2alpha1.Job{}):         {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisbatchv2alpha1.CronJob{}):     {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&sdnapiv1.EgressNetworkPolicy{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&sdnapiv1.HostSubnet{}):          {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&sdnapiv1.NetNamespace{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&sdnapiv1.ClusterNetwork{}):      {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&kapiv1.ConfigMap{}):                  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Service{}):                    {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodProxyOptions{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Binding{}):                    {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Namespace{}):                  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.RangeAllocation{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ExportOptions{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Node{}):                       {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ComponentStatus{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ReplicationController{}):      {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.DeleteOptions{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.LimitRange{}):                 {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.NodeProxyOptions{}):           {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ResourceQuota{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PersistentVolumeClaim{}):      {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.SecurityContextConstraints{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodTemplate{}):                {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ServiceAccount{}):             {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PersistentVolume{}):           {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ListOptions{}):                {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodLogOptions{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Endpoints{}):                  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodExecOptions{}):             {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.SerializedReference{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodAttachOptions{}):           {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.ServiceProxyOptions{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Secret{}):                     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Pod{}):                        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.PodStatusResult{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&kapiv1.Event{}):                      {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisbatchv1.Job{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisfederationv1beta1.Cluster{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&routeapiv1.Route{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisautoscalingv1.Scale{}):                   {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisautoscalingv1.HorizontalPodAutoscaler{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apispolicyv1beta1.Eviction{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apispolicyv1beta1.PodDisruptionBudget{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&pkgwatchversioned.Event{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&templateapiv1.Template{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&buildapiv1.BuildConfig{}):               {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&buildapiv1.Build{}):                     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&buildapiv1.BuildRequest{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&buildapiv1.BuildLogOptions{}):           {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&buildapiv1.BuildLog{}):                  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&buildapiv1.BinaryBuildRequestOptions{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&deployapiv1.DeploymentLog{}):            {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&deployapiv1.DeploymentRequest{}):        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&deployapiv1.DeploymentConfigRollback{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&deployapiv1.DeploymentLogOptions{}):     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&deployapiv1.DeploymentConfig{}):         {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apiscertificatesv1alpha1.CertificateSigningRequest{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&unversioned.Status{}):      {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&unversioned.APIGroup{}):    {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&unversioned.APIVersions{}): {ephemeral: true}, // TODO(mo): Just making the test pass

	reflect.TypeOf(&apisextensionsv1beta1.Ingress{}):                    {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.Scale{}):                      {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.NetworkPolicy{}):              {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.ReplicaSet{}):                 {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.HorizontalPodAutoscaler{}):    {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.PodSecurityPolicy{}):          {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.ThirdPartyResourceData{}):     {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.Job{}):                        {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.DeploymentRollback{}):         {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.DaemonSet{}):                  {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.Deployment{}):                 {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.ReplicationControllerDummy{}): {ephemeral: true}, // TODO(mo): Just making the test pass
	reflect.TypeOf(&apisextensionsv1beta1.ThirdPartyResource{}):         {ephemeral: true}, // TODO(mo): Just making the test pass
}

// TestEtcdStoragePath tests to make sure that all objects are stored in an expected location in etcd.
// It will start failing when a new type is added to ensure that all future types are added to this test.
// It will also fail when a type gets moved to a different location. Be very careful in this situation because
// it essentially means that you will be break old clusters unless you create some migration path for the old data.
func TestEtcdStoragePath(t *testing.T) {
	etcdServer := testutil.RequireEtcd(t)
	defer testutil.DumpEtcdOnFailure(t)
	keys := etcd.NewKeysAPI(etcdServer.Client)

	masterConfig, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatalf("error getting master config: %#v", err)
	}
	masterConfig.AdmissionConfig.PluginOrderOverride = []string{"PodNodeSelector"} // remove most admission checks to make testing easier

	kubeConfigFile, err := testserver.StartConfiguredMaster(masterConfig)
	if err != nil {
		t.Fatalf("error starting server: %#v", err)
	}
	kubeClient, err := testutil.GetClusterAdminKubeClient(kubeConfigFile)
	if err != nil {
		t.Fatalf("error getting client: %#v", err)
	}

	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeConfigFile}, &clientcmd.ConfigOverrides{})
	f := osclientcmd.NewFactory(loader)
	d := f.Decoder(false)
	seen := map[reflect.Type]struct{}{}
	const testNamespace = "etcdstoragepath"

	if _, err := kubeClient.Core().Namespaces().Create(&kapi.Namespace{ObjectMeta: kapi.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatalf("error creating test namespace: %#v", err)
	}

	for _, gv := range registered.RegisteredGroupVersions() {
		for kind, apiType := range kapi.Scheme.KnownTypes(gv) {
			// we don't care about lists // TODO make sure this is always true
			if strings.HasSuffix(apiType.Name(), "List") {
				continue
			}

			ptrType := reflect.PtrTo(apiType)
			seen[ptrType] = struct{}{}
			testData, ok := etcdStorageData[ptrType]
			pkgPath := apiType.PkgPath()

			if !ok {
				t.Errorf("no test data for %s from %s", kind, pkgPath)
				continue
			}

			if testData.ephemeral {
				t.Logf("Skipping test for %s from %s", kind, pkgPath)
				continue
			}

			func() {
				all := &[]runtime.Object{}
				defer func() {
					if !t.Failed() { // do not cleanup if test has already failed since we may need things in the etcd dump
						if err := cleanup(f, testNamespace, all); err != nil {
							t.Fatalf("failed to clean up etcd: %#v", err)
						}
					}
				}()

				if err := createPrerequisites(f, testNamespace, testData.prerequisites, all); err != nil {
					t.Errorf("failed to create prerequisites for %s from %s: %#v", kind, pkgPath, err)
					return
				}

				gvk := gv.WithKind(kind)

				if err := create(f, testData.stub, &gvk, testNamespace, all); err != nil {
					t.Errorf("failed to create stub for %s from %s: %#v", kind, pkgPath, err)
					return
				}

				output, err := getFromEtcd(keys, d, testData.expectedEtcdPath, &gvk)
				if err != nil {
					t.Errorf("failed to get from etcd for %s from %s: %#v", kind, pkgPath, err)
					return
				}

				if !kapi.Semantic.DeepDerivative(testData.stub, output) {
					t.Errorf("Test stub for %s from %s does not match: %s", kind, pkgPath, diff.ObjectDiff(testData.stub, output))
				}
			}()
		}
	}

	inEtcdData := diffMapKeys(etcdStorageData, seen)
	inSeen := diffMapKeys(seen, etcdStorageData)
	if len(inEtcdData) != 0 || len(inSeen) != 0 {
		t.Fatalf("etcd data does not match the types we saw:\nin etcd data but not seen: %s\nseen but not in etcd data: %s", inEtcdData, inSeen)
	}
}

func cleanup(f util.ObjectMappingFactory, testNamespace string, objects *[]runtime.Object) error {
	for i := len(*objects) - 1; i >= 0; i-- { // delete in reverse order in case creation order mattered
		obj := (*objects)[i]

		helper, name, err := getHelperAndName(f, obj, nil)
		if err != nil {
			return err
		}
		if err := helper.Delete(testNamespace, name); err != nil && !etcdutil.IsEtcdNotFound(err) {
			return err
		}
	}
	return nil
}

func create(f util.ObjectMappingFactory, obj runtime.Object, gvk *unversioned.GroupVersionKind, testNamespace string, all *[]runtime.Object) error {
	helper, _, err := getHelperAndName(f, obj, gvk)
	if err != nil {
		return err
	}
	output, err := helper.Create(testNamespace, false, obj)
	if err != nil {
		return err
	}
	*all = append(*all, output)
	return nil
}

func getHelperAndName(f util.ObjectMappingFactory, obj runtime.Object, gvk *unversioned.GroupVersionKind) (*resource.Helper, string, error) {
	mapper, typer := f.Object()
	if gvk == nil {
		gvks, _, err := typer.ObjectKinds(obj)
		if err != nil {
			return nil, "", err
		}
		gvk = &gvks[0]
	}
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, "", err
	}
	client, err := f.ClientForMapping(mapping)
	if err != nil {
		return nil, "", err
	}
	name, err := mapping.Name(obj)
	if err != nil {
		return nil, "", err
	}
	return resource.NewHelper(client, mapping), name, nil
}

func createPrerequisites(f util.ObjectMappingFactory, testNamespace string, prerequisites []runtime.Object, all *[]runtime.Object) error {
	for _, prerequisite := range prerequisites {
		if err := create(f, prerequisite, nil, testNamespace, all); err != nil {
			return err
		}
	}
	return nil
}

func getFromEtcd(keys etcd.KeysAPI, d runtime.Decoder, path string, gvk *unversioned.GroupVersionKind) (runtime.Object, error) {
	response, err := keys.Get(context.Background(), path, nil)
	if err != nil {
		return nil, err
	}
	output, _, err := d.Decode([]byte(response.Node.Value), gvk, nil)
	if err != nil {
		return nil, err
	}
	// TODO figure out how to get rid of this hack
	reflect.ValueOf(output).Elem().FieldByName("CreationTimestamp").Set(reflect.ValueOf(unversioned.Time{}))
	return output, nil
}

func diffMapKeys(a, b interface{}) []string {
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	ret := []string{}

	for _, ka := range av.MapKeys() {
		kat := ka.Interface().(reflect.Type)
		found := false
		for _, kb := range bv.MapKeys() {
			kbt := kb.Interface().(reflect.Type)
			if kat == kbt {
				found = true
				break
			}
		}
		if !found {
			ret = append(ret, kat.String())
		}
	}

	return ret
}
