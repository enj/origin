package integration

import (
	"reflect"
	"runtime/debug"
	"strings"
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	apiresource "k8s.io/kubernetes/pkg/api/resource"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kapiv1 "k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/apimachinery/registered"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/resource"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/diff"
	"k8s.io/kubernetes/pkg/util/intstr"

	"github.com/openshift/origin/pkg/authorization/authorizer/scope"
	osclientcmd "github.com/openshift/origin/pkg/cmd/util/clientcmd"
	saoauth "github.com/openshift/origin/pkg/serviceaccounts/oauthclient"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"

	// install all APIs
	_ "github.com/openshift/origin/pkg/api/install"

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
	sdnapi "github.com/openshift/origin/pkg/sdn/api"
	sdnapiv1 "github.com/openshift/origin/pkg/sdn/api/v1"
	securityapiv1 "github.com/openshift/origin/pkg/security/api/v1"
	templateapiv1 "github.com/openshift/origin/pkg/template/api/v1"
	userapiv1 "github.com/openshift/origin/pkg/user/api/v1"
)

// Etcd data for all persisted objects.  Be very careful when setting ephemeral to true as that removes the safety we gain from this test.
var etcdStorageData = map[reflect.Type]struct {
	ephemeral        bool             // Set to true to skip testing the object
	stub             runtime.Object   // Valid stub to use during create (this should have at least one field other than name)
	prerequisites    []runtime.Object // Optional, ordered list of objects to create before stub
	expectedEtcdPath string           // Expected location of object in etcd, do not use any variables, constants, etc to derive this value - always supply the full raw string
}{
	reflect.TypeOf(&oauthapiv1.OAuthClientAuthorization{}): {
		stub: &oauthapiv1.OAuthClientAuthorization{
			ClientName: "system:serviceaccount:etcdstoragepathtestnamespace:client",
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
		expectedEtcdPath: "openshift.io/oauth/clientauthorizations/user:system:serviceaccount:etcdstoragepathtestnamespace:client",
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
			ClientName: "client0",
			UserName:   "user",
			UserUID:    "cannot be empty",
		},
		prerequisites: []runtime.Object{
			&oauthapiv1.OAuthClient{
				ObjectMeta: kapiv1.ObjectMeta{Name: "client0"},
			},
		},
		expectedEtcdPath: "openshift.io/oauth/authorizetokens/tokenneedstobelongenoughelseitwontwork",
	},
	reflect.TypeOf(&oauthapiv1.OAuthAccessToken{}): {
		stub: &oauthapiv1.OAuthAccessToken{
			ObjectMeta: kapiv1.ObjectMeta{Name: "tokenneedstobelongenoughelseitwontwork"},
			ClientName: "client1",
			UserName:   "user",
			UserUID:    "cannot be empty",
		},
		prerequisites: []runtime.Object{
			&oauthapiv1.OAuthClient{
				ObjectMeta: kapiv1.ObjectMeta{Name: "client1"},
			},
		},
		expectedEtcdPath: "openshift.io/oauth/accesstokens/tokenneedstobelongenoughelseitwontwork",
	},
	reflect.TypeOf(&oauthapiv1.OAuthRedirectReference{}): {ephemeral: true}, // Used for specifying redirects, never stored in etcd

	reflect.TypeOf(&imageapidockerpre012.DockerImage{}): {ephemeral: true}, // part of imageapiv1.Image

	reflect.TypeOf(&imageapidocker10.DockerImage{}): {ephemeral: true}, // part of imageapiv1.Image

	reflect.TypeOf(&authorizationapiv1.PolicyBinding{}): {
		stub: &authorizationapiv1.PolicyBinding{
			RoleBindings: authorizationapiv1.NamedRoleBindings{
				{
					Name: "rb",
					RoleBinding: authorizationapiv1.RoleBinding{
						ObjectMeta: kapiv1.ObjectMeta{Name: "rb", Namespace: testNamespace},
						RoleRef:    kapiv1.ObjectReference{Name: "r"},
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/authorization/local/policybindings/etcdstoragepathtestnamespace/:default",
	},
	reflect.TypeOf(&authorizationapiv1.ClusterPolicyBinding{}): {
		stub: &authorizationapiv1.ClusterPolicyBinding{
			ObjectMeta: kapiv1.ObjectMeta{Name: "objectisincomparewhitelist"},
		},
		expectedEtcdPath: "openshift.io/authorization/cluster/policybindings/:default",
	},
	reflect.TypeOf(&authorizationapiv1.Policy{}): {
		stub: &authorizationapiv1.Policy{
			Roles: authorizationapiv1.NamedRoles{
				{
					Name: "r",
					Role: authorizationapiv1.Role{
						ObjectMeta: kapiv1.ObjectMeta{Name: "r", Namespace: testNamespace},
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/authorization/local/policies/etcdstoragepathtestnamespace/default",
	},
	reflect.TypeOf(&authorizationapiv1.ClusterPolicy{}): {
		stub: &authorizationapiv1.ClusterPolicy{
			ObjectMeta: kapiv1.ObjectMeta{Name: "objectisincomparewhitelist"},
		},
		expectedEtcdPath: "openshift.io/authorization/cluster/policies/default",
	},
	reflect.TypeOf(&authorizationapiv1.RoleBindingRestriction{}): {
		stub: &authorizationapiv1.RoleBindingRestriction{
			ObjectMeta: kapiv1.ObjectMeta{Name: "rbr"},
			Spec: authorizationapiv1.RoleBindingRestrictionSpec{
				ServiceAccountRestriction: &authorizationapiv1.ServiceAccountRestriction{
					ServiceAccounts: []authorizationapiv1.ServiceAccountReference{
						{
							Name: "sa",
						},
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/rolebindingrestrictions/etcdstoragepathtestnamespace/rbr",
	},

	// virtual objects that are not stored in etcd  // TODO this will change in the future when policies go away
	reflect.TypeOf(&authorizationapiv1.Role{}):               {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.ClusterRole{}):        {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.RoleBinding{}):        {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.ClusterRoleBinding{}): {ephemeral: true},

	// SAR objects that are not stored in etcd
	reflect.TypeOf(&authorizationapiv1.SubjectRulesReview{}):            {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.SelfSubjectRulesReview{}):        {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.SubjectAccessReview{}):           {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.ResourceAccessReview{}):          {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.LocalSubjectAccessReview{}):      {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.LocalResourceAccessReview{}):     {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.IsPersonalSubjectAccessReview{}): {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.ResourceAccessReviewResponse{}):  {ephemeral: true},
	reflect.TypeOf(&authorizationapiv1.SubjectAccessReviewResponse{}):   {ephemeral: true},

	// SAR objects that are not stored in etcd
	reflect.TypeOf(&apisauthorizationv1beta1.SelfSubjectAccessReview{}):  {ephemeral: true},
	reflect.TypeOf(&apisauthorizationv1beta1.LocalSubjectAccessReview{}): {ephemeral: true},
	reflect.TypeOf(&apisauthorizationv1beta1.SubjectAccessReview{}):      {ephemeral: true},

	reflect.TypeOf(&userapiv1.Group{}): {
		stub: &userapiv1.Group{
			ObjectMeta: kapiv1.ObjectMeta{Name: "group"},
			Users: userapiv1.OptionalNames{
				"user1", "user2",
			},
		},
		expectedEtcdPath: "openshift.io/groups/group",
	},
	reflect.TypeOf(&userapiv1.User{}): {
		stub: &userapiv1.User{
			ObjectMeta: kapiv1.ObjectMeta{Name: "user1"},
			FullName:   "user1",
		},
		expectedEtcdPath: "openshift.io/users/user1",
	},
	reflect.TypeOf(&userapiv1.Identity{}): {
		stub: &userapiv1.Identity{
			ObjectMeta:       kapiv1.ObjectMeta{Name: "github:user2"},
			ProviderName:     "github",
			ProviderUserName: "user2",
		},
		expectedEtcdPath: "openshift.io/useridentities/github:user2",
	},
	reflect.TypeOf(&userapiv1.UserIdentityMapping{}): {ephemeral: true}, // pointer from user to identity, not stored in etcd

	reflect.TypeOf(&projectapiv1.Project{}):        {ephemeral: true}, // proxy for namespace so cannot test here
	reflect.TypeOf(&projectapiv1.ProjectRequest{}): {ephemeral: true}, // not stored in etcd

	reflect.TypeOf(&apisimagepolicyv1alpha1.ImageReview{}): {ephemeral: true}, // not stored in etcd

	reflect.TypeOf(&quotaapiv1.ClusterResourceQuota{}): {
		stub: &quotaapiv1.ClusterResourceQuota{
			ObjectMeta: kapiv1.ObjectMeta{Name: "quota1"},
			Spec: quotaapiv1.ClusterResourceQuotaSpec{
				Selector: quotaapiv1.ClusterResourceQuotaSelector{
					LabelSelector: &unversioned.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/clusterresourcequotas/quota1",
	},
	reflect.TypeOf(&quotaapiv1.AppliedClusterResourceQuota{}): {ephemeral: true}, // mirror of ClusterResourceQuota that cannot be created

	// not stored in etcd
	reflect.TypeOf(&securityapiv1.PodSecurityPolicyReview{}):            {ephemeral: true},
	reflect.TypeOf(&securityapiv1.PodSecurityPolicySelfSubjectReview{}): {ephemeral: true},
	reflect.TypeOf(&securityapiv1.PodSecurityPolicySubjectReview{}):     {ephemeral: true},

	reflect.TypeOf(&apisstoragev1beta1.StorageClass{}): {
		stub: &apisstoragev1beta1.StorageClass{
			ObjectMeta:  kapiv1.ObjectMeta{Name: "sc1"},
			Provisioner: "aws",
		},
		expectedEtcdPath: "kubernetes.io/storageclasses/sc1",
	},

	// not stored in etcd
	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeSchedulerConfiguration{}): {ephemeral: true},
	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeletConfiguration{}):       {ephemeral: true},
	reflect.TypeOf(&apiscomponentconfigv1alpha1.KubeProxyConfiguration{}):     {ephemeral: true},

	reflect.TypeOf(&apisauthenticationv1beta1.TokenReview{}): {ephemeral: true}, // not stored in etcd

	// we cannot create these  // TODO but we should be able to create them in kube
	reflect.TypeOf(&apisrbacv1alpha1.RoleBinding{}):        {ephemeral: true},
	reflect.TypeOf(&apisrbacv1alpha1.Role{}):               {ephemeral: true},
	reflect.TypeOf(&apisrbacv1alpha1.ClusterRole{}):        {ephemeral: true},
	reflect.TypeOf(&apisrbacv1alpha1.ClusterRoleBinding{}): {ephemeral: true},

	reflect.TypeOf(&imageapiv1.Image{}): {
		stub: &imageapiv1.Image{
			ObjectMeta:           kapiv1.ObjectMeta{Name: "image1"},
			DockerImageReference: "fedora:latest",
		},
		expectedEtcdPath: "openshift.io/images/image1",
	},
	reflect.TypeOf(&imageapiv1.ImageStream{}): {
		stub: &imageapiv1.ImageStream{
			ObjectMeta: kapiv1.ObjectMeta{Name: "is1"},
			Spec: imageapiv1.ImageStreamSpec{
				DockerImageRepository: "docker",
			},
		},
		expectedEtcdPath: "openshift.io/imagestreams/etcdstoragepathtestnamespace/is1",
	},
	reflect.TypeOf(&imageapiv1.ImageStreamTag{}):     {ephemeral: true}, // part of image stream
	reflect.TypeOf(&imageapiv1.ImageSignature{}):     {ephemeral: true}, // part of image
	reflect.TypeOf(&imageapiv1.ImageStreamImport{}):  {ephemeral: true}, // not stored in etcd
	reflect.TypeOf(&imageapiv1.ImageStreamImage{}):   {ephemeral: true}, // not stored in etcd
	reflect.TypeOf(&imageapiv1.ImageStreamMapping{}): {ephemeral: true}, // not stored in etcd

	reflect.TypeOf(&apisappsv1beta1.StatefulSet{}): {
		stub: &apisappsv1beta1.StatefulSet{
			ObjectMeta: kapiv1.ObjectMeta{Name: "ss1"},
			Spec: apisappsv1beta1.StatefulSetSpec{
				Template: kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"a": "b",
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/statefulsets/etcdstoragepathtestnamespace/ss1",
	},

	reflect.TypeOf(&apisbatchv2alpha1.CronJob{}): {
		stub: &apisbatchv2alpha1.CronJob{
			ObjectMeta: kapiv1.ObjectMeta{Name: "cj1"},
			Spec: apisbatchv2alpha1.CronJobSpec{
				Schedule: "* * * * *",
				JobTemplate: apisbatchv2alpha1.JobTemplateSpec{
					Spec: apisbatchv2alpha1.JobSpec{
						Template: kapiv1.PodTemplateSpec{
							ObjectMeta: kapiv1.ObjectMeta{
								Labels: map[string]string{
									"controller-uid": "uid0",
								},
							},
							Spec: kapiv1.PodSpec{
								Containers: []kapiv1.Container{
									{Name: "container0", Image: "fedora:latest"},
								},
								RestartPolicy: kapiv1.RestartPolicyNever,
								DNSPolicy:     kapiv1.DNSClusterFirst,
							},
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/cronjobs/etcdstoragepathtestnamespace/cj1",
	},
	reflect.TypeOf(&apisbatchv2alpha1.Job{}):         {ephemeral: true}, // creating this makes a apisbatchv1.Job so test that instead
	reflect.TypeOf(&apisbatchv2alpha1.JobTemplate{}): {ephemeral: true}, // not stored in etcd

	reflect.TypeOf(&sdnapiv1.EgressNetworkPolicy{}): {
		stub: &sdnapiv1.EgressNetworkPolicy{
			ObjectMeta: kapiv1.ObjectMeta{Name: "enp1"},
			Spec: sdnapiv1.EgressNetworkPolicySpec{
				Egress: []sdnapiv1.EgressNetworkPolicyRule{
					{Type: sdnapiv1.EgressNetworkPolicyRuleAllow, To: sdnapiv1.EgressNetworkPolicyPeer{CIDRSelector: "192.168.1.1/24"}},
				},
			},
		},
		expectedEtcdPath: "openshift.io/registry/egressnetworkpolicy/etcdstoragepathtestnamespace/enp1",
	},
	reflect.TypeOf(&sdnapiv1.HostSubnet{}): {
		stub: &sdnapiv1.HostSubnet{
			ObjectMeta: kapiv1.ObjectMeta{Name: "hs1"}, // This will fail to delete because meta.name != Host but it is keyed off Host
			Host:       "hostname",
			HostIP:     "192.168.1.1",
			Subnet:     "192.168.1.1/24",
		},
		expectedEtcdPath: "openshift.io/registry/sdnsubnets/hostname",
	},
	reflect.TypeOf(&sdnapiv1.NetNamespace{}): {
		stub: &sdnapiv1.NetNamespace{
			ObjectMeta: kapiv1.ObjectMeta{Name: "nn1"}, // This will fail to delete because meta.name != NetName but it is keyed off NetName
			NetName:    "networkname",
			NetID:      100,
		},
		expectedEtcdPath: "openshift.io/registry/sdnnetnamespaces/networkname",
	},
	reflect.TypeOf(&sdnapiv1.ClusterNetwork{}): {
		stub: &sdnapiv1.ClusterNetwork{
			ObjectMeta:     kapiv1.ObjectMeta{Name: "cn1"},
			Network:        "192.168.0.1/24",
			ServiceNetwork: "192.168.1.1/24",
		},
		expectedEtcdPath: "openshift.io/registry/sdnnetworks/cn1",
	},

	reflect.TypeOf(&kapiv1.ConfigMap{}): {
		stub: &kapiv1.ConfigMap{
			ObjectMeta: kapiv1.ObjectMeta{Name: "cm1"},
			Data: map[string]string{
				"foo": "bar",
			},
		},
		expectedEtcdPath: "kubernetes.io/configmaps/etcdstoragepathtestnamespace/cm1",
	},
	reflect.TypeOf(&kapiv1.Service{}): {
		stub: &kapiv1.Service{
			ObjectMeta: kapiv1.ObjectMeta{Name: "service1"},
			Spec: kapiv1.ServiceSpec{
				ExternalName: "service1name",
				Ports: []kapiv1.ServicePort{
					{
						Port:       10000,
						TargetPort: intstr.FromInt(11000),
					},
				},
				Selector: map[string]string{
					"test": "data",
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/services/specs/etcdstoragepathtestnamespace/service1",
	},
	reflect.TypeOf(&kapiv1.Namespace{}): {
		stub: &kapiv1.Namespace{
			ObjectMeta: kapiv1.ObjectMeta{Name: "namespace1"},
			Spec: kapiv1.NamespaceSpec{
				Finalizers: []kapiv1.FinalizerName{
					kapiv1.FinalizerKubernetes,
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/namespaces/namespace1",
	},
	reflect.TypeOf(&kapiv1.Node{}): {
		stub: &kapiv1.Node{
			ObjectMeta: kapiv1.ObjectMeta{Name: "node1"},
			Spec: kapiv1.NodeSpec{
				Unschedulable: true,
			},
		},
		expectedEtcdPath: "kubernetes.io/minions/node1",
	},
	reflect.TypeOf(&kapiv1.Event{}): {
		stub: &kapiv1.Event{
			ObjectMeta: kapiv1.ObjectMeta{Name: "event1"},
			Message:    "some data here",
			InvolvedObject: kapiv1.ObjectReference{
				Namespace: testNamespace,
			},
		},
		expectedEtcdPath: "kubernetes.io/events/etcdstoragepathtestnamespace/event1",
	},
	reflect.TypeOf(&kapiv1.Secret{}): {
		stub: &kapiv1.Secret{
			ObjectMeta: kapiv1.ObjectMeta{Name: "secret1"},
			Data: map[string][]byte{
				"key": []byte("data file"),
			},
		},
		expectedEtcdPath: "kubernetes.io/secrets/etcdstoragepathtestnamespace/secret1",
	},
	reflect.TypeOf(&kapiv1.Pod{}): {
		stub: &kapiv1.Pod{
			ObjectMeta: kapiv1.ObjectMeta{Name: "pod1"},
			Spec: kapiv1.PodSpec{
				Containers: []kapiv1.Container{
					{Name: "container7", Image: "fedora:latest"},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/pods/etcdstoragepathtestnamespace/pod1",
	},
	reflect.TypeOf(&kapiv1.ServiceAccount{}): {
		stub: &kapiv1.ServiceAccount{
			ObjectMeta: kapiv1.ObjectMeta{Name: "sa1name"},
			Secrets: []kapiv1.ObjectReference{
				{Name: "secret00"},
			},
		},
		expectedEtcdPath: "kubernetes.io/serviceaccounts/etcdstoragepathtestnamespace/sa1name",
	},
	reflect.TypeOf(&kapiv1.ReplicationController{}): {
		stub: &kapiv1.ReplicationController{
			ObjectMeta: kapiv1.ObjectMeta{Name: "rc1"},
			Spec: kapiv1.ReplicationControllerSpec{
				Selector: map[string]string{
					"new": "stuff",
				},
				Template: &kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"new": "stuff",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container8", Image: "fedora:latest"},
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/controllers/etcdstoragepathtestnamespace/rc1",
	},
	reflect.TypeOf(&kapiv1.PersistentVolume{}): {
		stub: &kapiv1.PersistentVolume{
			ObjectMeta: kapiv1.ObjectMeta{Name: "pv1name"},
			Spec: kapiv1.PersistentVolumeSpec{
				AccessModes: []kapiv1.PersistentVolumeAccessMode{
					kapiv1.ReadWriteOnce,
				},
				Capacity: kapiv1.ResourceList{
					kapiv1.ResourceStorage: apiresource.MustParse("3.0"),
				},
				PersistentVolumeSource: kapiv1.PersistentVolumeSource{
					HostPath: &kapiv1.HostPathVolumeSource{
						Path: "/tmp/test/",
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/persistentvolumes/pv1name",
	},
	reflect.TypeOf(&kapiv1.PersistentVolumeClaim{}): {
		stub: &kapiv1.PersistentVolumeClaim{
			ObjectMeta: kapiv1.ObjectMeta{Name: "pvc1"},
			Spec: kapiv1.PersistentVolumeClaimSpec{
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"pvc": "stuff",
					},
				},
				AccessModes: []kapiv1.PersistentVolumeAccessMode{
					kapiv1.ReadWriteOnce,
				},
				Resources: kapiv1.ResourceRequirements{
					Limits: kapiv1.ResourceList{
						kapiv1.ResourceStorage: apiresource.MustParse("1.0"),
					},
					Requests: kapiv1.ResourceList{
						kapiv1.ResourceStorage: apiresource.MustParse("2.0"),
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/persistentvolumeclaims/etcdstoragepathtestnamespace/pvc1",
	},
	reflect.TypeOf(&kapiv1.SecurityContextConstraints{}): {
		stub: &kapiv1.SecurityContextConstraints{
			ObjectMeta:               kapiv1.ObjectMeta{Name: "scc1"},
			AllowPrivilegedContainer: true,
			RunAsUser: kapiv1.RunAsUserStrategyOptions{
				Type: kapiv1.RunAsUserStrategyRunAsAny,
			},
			SELinuxContext: kapiv1.SELinuxContextStrategyOptions{
				Type: kapiv1.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: kapiv1.SupplementalGroupsStrategyOptions{
				Type: kapiv1.SupplementalGroupsStrategyRunAsAny,
			},
			FSGroup: kapiv1.FSGroupStrategyOptions{
				Type: kapiv1.FSGroupStrategyRunAsAny,
			},
		},
		expectedEtcdPath: "kubernetes.io/securitycontextconstraints/scc1",
	},
	reflect.TypeOf(&kapiv1.ResourceQuota{}): {
		stub: &kapiv1.ResourceQuota{
			ObjectMeta: kapiv1.ObjectMeta{Name: "rq1name"},
			Spec: kapiv1.ResourceQuotaSpec{
				Hard: kapiv1.ResourceList{
					kapiv1.ResourceCPU: apiresource.MustParse("5.0"),
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/resourcequotas/etcdstoragepathtestnamespace/rq1name",
	},
	reflect.TypeOf(&kapiv1.LimitRange{}): {
		stub: &kapiv1.LimitRange{
			ObjectMeta: kapiv1.ObjectMeta{Name: "lr1name"},
			Spec: kapiv1.LimitRangeSpec{
				Limits: []kapiv1.LimitRangeItem{
					{Type: kapiv1.LimitTypePod},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/limitranges/etcdstoragepathtestnamespace/lr1name",
	},
	reflect.TypeOf(&kapiv1.PodTemplate{}): {
		stub: &kapiv1.PodTemplate{
			ObjectMeta: kapiv1.ObjectMeta{Name: "pt1name"},
			Template: kapiv1.PodTemplateSpec{
				ObjectMeta: kapiv1.ObjectMeta{
					Labels: map[string]string{
						"pt": "01",
					},
				},
				Spec: kapiv1.PodSpec{
					Containers: []kapiv1.Container{
						{Name: "container9", Image: "fedora:latest"},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/podtemplates/etcdstoragepathtestnamespace/pt1name",
	},
	reflect.TypeOf(&kapiv1.Endpoints{}): {
		stub: &kapiv1.Endpoints{
			ObjectMeta: kapiv1.ObjectMeta{Name: "ep1name"},
			Subsets: []kapiv1.EndpointSubset{
				{
					Addresses: []kapiv1.EndpointAddress{
						{Hostname: "bar-001", IP: "192.168.3.1"},
					},
					Ports: []kapiv1.EndpointPort{
						{Port: 8000},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/services/endpoints/etcdstoragepathtestnamespace/ep1name",
	},
	reflect.TypeOf(&kapiv1.Binding{}):             {ephemeral: true}, // annotation on pod, not stored in etcd
	reflect.TypeOf(&kapiv1.RangeAllocation{}):     {ephemeral: true}, // stored in various places in etcd but cannot be directly created // TODO maybe possible in kube
	reflect.TypeOf(&kapiv1.ComponentStatus{}):     {ephemeral: true}, // status info not stored in etcd
	reflect.TypeOf(&kapiv1.SerializedReference{}): {ephemeral: true}, // used for serilization, not stored in etcd
	reflect.TypeOf(&kapiv1.PodStatusResult{}):     {ephemeral: true}, // wrapper object not stored in etcd
	// used in queries, not stored in etcd
	reflect.TypeOf(&kapiv1.ListOptions{}):         {ephemeral: true},
	reflect.TypeOf(&kapiv1.DeleteOptions{}):       {ephemeral: true},
	reflect.TypeOf(&kapiv1.ExportOptions{}):       {ephemeral: true},
	reflect.TypeOf(&kapiv1.PodLogOptions{}):       {ephemeral: true},
	reflect.TypeOf(&kapiv1.PodExecOptions{}):      {ephemeral: true},
	reflect.TypeOf(&kapiv1.PodAttachOptions{}):    {ephemeral: true},
	reflect.TypeOf(&kapiv1.PodProxyOptions{}):     {ephemeral: true},
	reflect.TypeOf(&kapiv1.NodeProxyOptions{}):    {ephemeral: true},
	reflect.TypeOf(&kapiv1.ServiceProxyOptions{}): {ephemeral: true},

	reflect.TypeOf(&apisbatchv1.Job{}): {
		stub: &apisbatchv1.Job{
			ObjectMeta: kapiv1.ObjectMeta{Name: "job1"},
			Spec: apisbatchv1.JobSpec{
				ManualSelector: func() *bool { b := true; return &b }(),
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"controller-uid": "uid1",
					},
				},
				Template: kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"controller-uid": "uid1",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container1", Image: "fedora:latest"},
						},
						RestartPolicy: kapiv1.RestartPolicyNever,
						DNSPolicy:     kapiv1.DNSClusterFirst,
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/jobs/etcdstoragepathtestnamespace/job1",
	},

	reflect.TypeOf(&apisfederationv1beta1.Cluster{}): {ephemeral: true}, // we cannot create this  // TODO but we should be able to create it in kube

	reflect.TypeOf(&routeapiv1.Route{}): {
		stub: &routeapiv1.Route{
			ObjectMeta: kapiv1.ObjectMeta{Name: "route1"},
			Spec: routeapiv1.RouteSpec{
				Host: "hostname1",
				To: routeapiv1.RouteTargetReference{
					Name: "service1",
				},
			},
		},
		expectedEtcdPath: "openshift.io/routes/etcdstoragepathtestnamespace/route1",
	},

	reflect.TypeOf(&apisautoscalingv1.HorizontalPodAutoscaler{}): {ephemeral: true}, // creating this returns a apisextensionsv1beta1.HorizontalPodAutoscaler so test that instead
	reflect.TypeOf(&apisautoscalingv1.Scale{}):                   {ephemeral: true}, // not stored in etcd, part of kapiv1.ReplicationController

	reflect.TypeOf(&apispolicyv1beta1.PodDisruptionBudget{}): {
		stub: &apispolicyv1beta1.PodDisruptionBudget{
			ObjectMeta: kapiv1.ObjectMeta{Name: "pdb1"},
			Spec: apispolicyv1beta1.PodDisruptionBudgetSpec{
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"anokkey": "anokvalue",
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/poddisruptionbudgets/etcdstoragepathtestnamespace/pdb1",
	},
	reflect.TypeOf(&apispolicyv1beta1.Eviction{}): {ephemeral: true}, // not stored in etcd, deals with evicting kapiv1.Pod

	reflect.TypeOf(&pkgwatchversioned.Event{}): {ephemeral: true}, // watch events are not stored in etcd

	reflect.TypeOf(&templateapiv1.Template{}): {
		stub: &templateapiv1.Template{
			ObjectMeta: kapiv1.ObjectMeta{Name: "template1"},
			Message:    "Jenkins template",
		},
		expectedEtcdPath: "openshift.io/templates/etcdstoragepathtestnamespace/template1",
	},

	reflect.TypeOf(&buildapiv1.BuildConfig{}): {
		stub: &buildapiv1.BuildConfig{
			ObjectMeta: kapiv1.ObjectMeta{Name: "bc1"},
			Spec: buildapiv1.BuildConfigSpec{
				CommonSpec: buildapiv1.CommonSpec{
					Strategy: buildapiv1.BuildStrategy{
						DockerStrategy: &buildapiv1.DockerBuildStrategy{
							NoCache: true,
						},
					},
					Source: buildapiv1.BuildSource{
						Dockerfile: func() *string { s := "Dockerfile0"; return &s }(),
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/buildconfigs/etcdstoragepathtestnamespace/bc1",
	},
	reflect.TypeOf(&buildapiv1.Build{}): {
		stub: &buildapiv1.Build{
			ObjectMeta: kapiv1.ObjectMeta{Name: "build1"},
			Spec: buildapiv1.BuildSpec{
				CommonSpec: buildapiv1.CommonSpec{
					Strategy: buildapiv1.BuildStrategy{
						DockerStrategy: &buildapiv1.DockerBuildStrategy{
							NoCache: true,
						},
					},
					Source: buildapiv1.BuildSource{
						Dockerfile: func() *string { s := "Dockerfile1"; return &s }(),
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/builds/etcdstoragepathtestnamespace/build1",
	},
	// used for streaming build logs from pod, not stored in etcd
	reflect.TypeOf(&buildapiv1.BuildLog{}):        {ephemeral: true},
	reflect.TypeOf(&buildapiv1.BuildLogOptions{}): {ephemeral: true},
	// BuildGenerator helpers not stored in etcd
	reflect.TypeOf(&buildapiv1.BuildRequest{}):              {ephemeral: true},
	reflect.TypeOf(&buildapiv1.BinaryBuildRequestOptions{}): {ephemeral: true},

	reflect.TypeOf(&deployapiv1.DeploymentConfig{}): {
		stub: &deployapiv1.DeploymentConfig{
			ObjectMeta: kapiv1.ObjectMeta{Name: "dc1"},
			Spec: deployapiv1.DeploymentConfigSpec{
				Selector: map[string]string{
					"d": "c",
				},
				Template: &kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"d": "c",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container2", Image: "fedora:latest"},
						},
					},
				},
			},
		},
		expectedEtcdPath: "openshift.io/deploymentconfigs/etcdstoragepathtestnamespace/dc1",
	},
	// used for streaming deployment logs from pod, not stored in etcd
	reflect.TypeOf(&deployapiv1.DeploymentLog{}):            {ephemeral: true},
	reflect.TypeOf(&deployapiv1.DeploymentLogOptions{}):     {ephemeral: true},
	reflect.TypeOf(&deployapiv1.DeploymentRequest{}):        {ephemeral: true}, // triggers new dc, not stored in etcd
	reflect.TypeOf(&deployapiv1.DeploymentConfigRollback{}): {ephemeral: true}, // triggers rolleback dc, not stored in etcd

	reflect.TypeOf(&apiscertificatesv1alpha1.CertificateSigningRequest{}): {
		stub: &apiscertificatesv1alpha1.CertificateSigningRequest{
			ObjectMeta: kapiv1.ObjectMeta{Name: "csr1"},
			Spec: apiscertificatesv1alpha1.CertificateSigningRequestSpec{
				Request: []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIByjCCATMCAQAwgYkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMR8w
HQYDVQQLExZJbmZvcm1hdGlvbiBUZWNobm9sb2d5MRcwFQYDVQQDEw53d3cuZ29v
Z2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApZtYJCHJ4VpVXHfV
IlstQTlO4qC03hjX+ZkPyvdYd1Q4+qbAeTwXmCUKYHThVRd5aXSqlPzyIBwieMZr
WFlRQddZ1IzXAlVRDWwAo60KecqeAXnnUK+5fXoTI/UgWshre8tJ+x/TMHaQKR/J
cIWPhqaQhsJuzZbvAdGA80BLxdMCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA4GBAIhl
4PvFq+e7ipARgI5ZM+GZx6mpCz44DTo0JkwfRDf+BtrsaC0q68eTf2XhYOsq4fkH
Q0uA0aVog3f5iJxCa3Hp5gxbJQ6zV6kJ0TEsuaaOhEko9sdpCoPOnRBm2i/XRD2D
6iNh8f8z0ShGsFqjDgFHyF3o+lUyj+UC6H1QW7bn
-----END CERTIFICATE REQUEST-----`),
			},
		},
		expectedEtcdPath: "kubernetes.io/certificatesigningrequests/csr1",
	},

	reflect.TypeOf(&unversioned.Status{}):      {ephemeral: true}, // return value for calls, not stored in etcd
	reflect.TypeOf(&unversioned.APIGroup{}):    {ephemeral: true}, // not stored in etcd
	reflect.TypeOf(&unversioned.APIVersions{}): {ephemeral: true}, // not stored in etcd

	reflect.TypeOf(&apisextensionsv1beta1.Ingress{}): {
		stub: &apisextensionsv1beta1.Ingress{
			ObjectMeta: kapiv1.ObjectMeta{Name: "ingress1"},
			Spec: apisextensionsv1beta1.IngressSpec{
				Backend: &apisextensionsv1beta1.IngressBackend{
					ServiceName: "service",
					ServicePort: intstr.FromInt(5000),
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/ingress/etcdstoragepathtestnamespace/ingress1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.NetworkPolicy{}): {
		stub: &apisextensionsv1beta1.NetworkPolicy{
			ObjectMeta: kapiv1.ObjectMeta{Name: "np1"},
			Spec: apisextensionsv1beta1.NetworkPolicySpec{
				PodSelector: unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"e": "f",
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/networkpolicies/etcdstoragepathtestnamespace/np1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.ReplicaSet{}): {
		stub: &apisextensionsv1beta1.ReplicaSet{
			ObjectMeta: kapiv1.ObjectMeta{Name: "rs1"},
			Spec: apisextensionsv1beta1.ReplicaSetSpec{
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"g": "h",
					},
				},
				Template: kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"g": "h",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container4", Image: "fedora:latest"},
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/replicasets/etcdstoragepathtestnamespace/rs1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.HorizontalPodAutoscaler{}): {
		stub: &apisextensionsv1beta1.HorizontalPodAutoscaler{
			ObjectMeta: kapiv1.ObjectMeta{Name: "hpa1"},
			Spec: apisextensionsv1beta1.HorizontalPodAutoscalerSpec{
				MaxReplicas: 3,
				ScaleRef: apisextensionsv1beta1.SubresourceReference{
					Name: "cross",
					Kind: "something",
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/horizontalpodautoscalers/etcdstoragepathtestnamespace/hpa1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.PodSecurityPolicy{}): {
		stub: &apisextensionsv1beta1.PodSecurityPolicy{
			ObjectMeta: kapiv1.ObjectMeta{Name: "psp1"},
			Spec: apisextensionsv1beta1.PodSecurityPolicySpec{
				Privileged: true,
				RunAsUser: apisextensionsv1beta1.RunAsUserStrategyOptions{
					Rule: apisextensionsv1beta1.RunAsUserStrategyRunAsAny,
				},
				SELinux: apisextensionsv1beta1.SELinuxStrategyOptions{
					Rule: apisextensionsv1beta1.SELinuxStrategyMustRunAs,
				},
				SupplementalGroups: apisextensionsv1beta1.SupplementalGroupsStrategyOptions{
					Rule: apisextensionsv1beta1.SupplementalGroupsStrategyRunAsAny,
				},
				FSGroup: apisextensionsv1beta1.FSGroupStrategyOptions{
					Rule: apisextensionsv1beta1.FSGroupStrategyRunAsAny,
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/podsecuritypolicy/psp1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.ThirdPartyResource{}): {
		stub: &apisextensionsv1beta1.ThirdPartyResource{
			ObjectMeta:  kapiv1.ObjectMeta{Name: "kind.domain.tld"},
			Description: "third party",
			Versions: []apisextensionsv1beta1.APIVersion{
				{Name: "v3"},
			},
		},
		expectedEtcdPath: "kubernetes.io/thirdpartyresources/kind.domain.tld",
	},
	reflect.TypeOf(&apisextensionsv1beta1.DaemonSet{}): {
		stub: &apisextensionsv1beta1.DaemonSet{
			ObjectMeta: kapiv1.ObjectMeta{Name: "ds1"},
			Spec: apisextensionsv1beta1.DaemonSetSpec{
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"u": "t",
					},
				},
				Template: kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"u": "t",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container5", Image: "fedora:latest"},
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/daemonsets/etcdstoragepathtestnamespace/ds1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.Deployment{}): {
		stub: &apisextensionsv1beta1.Deployment{
			ObjectMeta: kapiv1.ObjectMeta{Name: "deployment1"},
			Spec: apisextensionsv1beta1.DeploymentSpec{
				Selector: &unversioned.LabelSelector{
					MatchLabels: map[string]string{
						"f": "z",
					},
				},
				Template: kapiv1.PodTemplateSpec{
					ObjectMeta: kapiv1.ObjectMeta{
						Labels: map[string]string{
							"f": "z",
						},
					},
					Spec: kapiv1.PodSpec{
						Containers: []kapiv1.Container{
							{Name: "container6", Image: "fedora:latest"},
						},
					},
				},
			},
		},
		expectedEtcdPath: "kubernetes.io/deployments/etcdstoragepathtestnamespace/deployment1",
	},
	reflect.TypeOf(&apisextensionsv1beta1.DeploymentRollback{}):         {ephemeral: true}, // used to rollback deployment, not stored in etcd
	reflect.TypeOf(&apisextensionsv1beta1.ReplicationControllerDummy{}): {ephemeral: true}, // not stored in etcd
	reflect.TypeOf(&apisextensionsv1beta1.Job{}):                        {ephemeral: true}, // creating this makes a apisbatchv1.Job so test that instead
	reflect.TypeOf(&apisextensionsv1beta1.Scale{}):                      {ephemeral: true}, // not stored in etcd, part of kapiv1.ReplicationController
	reflect.TypeOf(&apisextensionsv1beta1.ThirdPartyResourceData{}):     {ephemeral: true}, // we cannot create this  // TODO but we should be able to create it in kube
}

// namespace used for all tests, do not change this
const testNamespace = "etcdstoragepathtestnamespace"

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
				t.Errorf("no test data for %s from %s.  Please add a test for your new type to etcdStorageData.", kind, pkgPath)
				continue
			}

			if testData.ephemeral { // TODO it would be nice if we could remove this and infer if an object is not stored in etcd
				t.Logf("Skipping test for %s from %s", kind, pkgPath)
				continue
			}

			if isInKindAndPathWhiteList(kind, pkgPath) {
				t.Logf("kind and path are whitelisted: skipping test for %s from %s", kind, pkgPath)
				continue
			}

			if len(testData.expectedEtcdPath) == 0 || testData.stub == nil || reflect.TypeOf(testData.stub) != ptrType || isZero(reflect.ValueOf(testData.stub)) {
				t.Errorf("invalid test data for %s from %s", kind, pkgPath)
				continue
			}

			func() { // forces defer to run per iteration of the for loop
				all := &[]runtime.Object{}
				defer func() {
					if !t.Failed() { // do not cleanup if test has already failed since we may need things in the etcd dump
						if err := cleanup(f, testNamespace, all); err != nil {
							t.Fatalf("failed to clean up etcd: %#v", err)
						}
					}
					// We create a lot of TCP connections in a tight loop.
					// This frees them so we do not run out of file descriptors.
					debug.FreeOSMemory()
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

				// just check the type of whitelisted items
				if isInCreateAndCompareWhiteList(output) {
					outputType := reflect.TypeOf(output)
					if outputType != ptrType {
						t.Errorf("Output for %s from %s has the wrong type, expected %s, got %s", kind, pkgPath, ptrType.String(), outputType.String())
					}
					return
				}

				if !kapi.Semantic.DeepDerivative(testData.stub, output) {
					t.Errorf("Test stub for %s from %s does not match: %s", kind, pkgPath, diff.ObjectGoPrintDiff(testData.stub, output))
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

func isInCreateAndCompareWhiteList(obj runtime.Object) bool {
	switch obj.(type) {
	case *authorizationapiv1.ClusterPolicyBinding, *authorizationapiv1.ClusterPolicy: // TODO figure out how to not whitelist these
		return true
		// Removed this case per soltysh's request to not have so many exceptions, but leaving here so people are not confused by the errors
		//case *apisbatchv2alpha1.CronJob: // since we do not cleanup once a test is failed, we will get an AlreadyExists error since ScheduledJob aliases CronJob
		//	return true
	}
	return false
}

func isInInvalidNameWhiteList(obj runtime.Object) bool {
	switch obj.(type) {
	case *sdnapi.HostSubnet, *sdnapi.NetNamespace: // TODO figure out how to not whitelist these
		return true
	}
	return false
}

func isInKindAndPathWhiteList(kind, pkgPath string) bool {
	switch {
	// aliases for templateapiv1.Template
	case kind == "TemplateConfig" && pkgPath == "github.com/openshift/origin/pkg/template/api/v1",
		kind == "ProcessedTemplate" && pkgPath == "github.com/openshift/origin/pkg/template/api/v1":
		return true
	}
	return false
}

func cleanup(f util.ObjectMappingFactory, testNamespace string, objects *[]runtime.Object) error {
	for i := len(*objects) - 1; i >= 0; i-- { // delete in reverse order in case creation order mattered
		obj := (*objects)[i]

		helper, name, err := getHelperAndName(f, obj, nil)
		if err != nil {
			return err
		}
		if err := helper.Delete(testNamespace, name); err != nil {
			if kubeerr.IsNotFound(err) && isInInvalidNameWhiteList(obj) {
				return nil
			}
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
		if kubeerr.IsAlreadyExists(err) && isInCreateAndCompareWhiteList(obj) {
			return nil
		}
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
	return unsetProblematicFields(output), nil
}

// TODO figure out how to get rid of this hack
func unsetProblematicFields(obj runtime.Object) runtime.Object {
	e := reflect.ValueOf(obj).Elem()
	for fieldName, fieldValue := range map[string]interface{}{
		"CreationTimestamp": unversioned.Time{},
		"Generation":        int64(0),
	} {
		e.FieldByName(fieldName).Set(reflect.ValueOf(fieldValue))
	}
	return obj
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

// TODO replace with reflect.IsZero when that gets added in 1.9
func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	case reflect.Array:
		z := true
		for i := 0; i < v.Len(); i++ {
			z = z && isZero(v.Index(i))
		}
		return z
	case reflect.Struct:
		z := true
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				z = z && isZero(v.Field(i))
			}
		}
		return z
	case reflect.Ptr:
		return isZero(reflect.Indirect(v))
	}
	if !v.IsValid() {
		return true
	}
	// Compare other types directly:
	z := reflect.Zero(v.Type())
	return v.Interface() == z.Interface()
}
