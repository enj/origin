package integration

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/meta"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/client/restclient"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/diff"
	"k8s.io/kubernetes/pkg/util/flowcontrol"

	"github.com/openshift/origin/pkg/api/latest"
	osclientcmd "github.com/openshift/origin/pkg/cmd/util/clientcmd"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"

	// install all APIs
	_ "github.com/openshift/origin/pkg/api/install"

	etcd "github.com/coreos/etcd/client"
	"golang.org/x/net/context"

	authorizationapiv1 "github.com/openshift/origin/pkg/authorization/api/v1"
	sdnapi "github.com/openshift/origin/pkg/sdn/api"
)

// Etcd data for all persisted objects.  Be very careful when setting ephemeral to true as that removes the safety we gain from this test.
var etcdStorageData = map[unversioned.GroupVersionResource]struct {
	ephemeral        bool           // Set to true to skip testing the object
	stub             string         // Valid JSON stub to use during create (this should have at least one field other than name)
	prerequisites    []prerequisite // Optional, ordered list of JSON objects to create before stub
	expectedEtcdPath string         // Expected location of object in etcd, do not use any variables, constants, etc to derive this value - always supply the full raw string
}{
	// github.com/openshift/origin/pkg/authorization/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusterpolicybindings"}: {
		stub:             `{"metadata": {"name": "objectisincomparewhitelist"}}`,
		expectedEtcdPath: "openshift.io/authorization/cluster/policybindings/:default",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusterpolicies"}: {
		stub:             `{"metadata": {"name": "objectisincomparewhitelist"}}`,
		expectedEtcdPath: "openshift.io/authorization/cluster/policies/default",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "policybindings"}: {
		stub:             `{"roleBindings": [{"name": "rb", "roleBinding": {"metadata": {"name": "rb", "namespace": "etcdstoragepathtestnamespace"}, "roleRef": {"name": "r"}}}]}`,
		expectedEtcdPath: "openshift.io/authorization/local/policybindings/etcdstoragepathtestnamespace/:default",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "rolebindingrestrictions"}: {
		stub:             `{"metadata": {"name": "rbr"}, "spec": {"serviceaccountrestriction": {"serviceaccounts": [{"name": "sa"}]}}}`,
		expectedEtcdPath: "openshift.io/rolebindingrestrictions/etcdstoragepathtestnamespace/rbr",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "policies"}: {
		stub:             `{"roles": [{"name": "r", "role": {"metadata": {"name": "r", "namespace": "etcdstoragepathtestnamespace"}}}]}`,
		expectedEtcdPath: "openshift.io/authorization/local/policies/etcdstoragepathtestnamespace/default",
	},

	// virtual objects that are not stored in etcd  // TODO this will change in the future when policies go away
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "roles"}:               {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusterroles"}:        {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "rolebindings"}:        {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusterrolebindings"}: {ephemeral: true},

	// SAR objects that are not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "subjectrulesreviews"}:            {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "selfsubjectrulesreviews"}:        {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "subjectaccessreviews"}:           {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "resourceaccessreviews"}:          {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "localsubjectaccessreviews"}:      {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "localresourceaccessreviews"}:     {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "ispersonalsubjectaccessreviews"}: {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "resourceaccessreviewresponses"}:  {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "subjectaccessreviewresponses"}:   {ephemeral: true},
	// --

	// github.com/openshift/origin/pkg/build/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "builds"}: {
		stub:             `{"metadata": {"name": "build1"}, "spec": {"source": {"dockerfile": "Dockerfile1"}, "strategy": {"dockerStrategy": {"noCache": true}}}}`,
		expectedEtcdPath: "openshift.io/builds/etcdstoragepathtestnamespace/build1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "buildconfigs"}: {
		stub:             `{"metadata": {"name": "bc1"}, "spec": {"source": {"dockerfile": "Dockerfile0"}, "strategy": {"dockerStrategy": {"noCache": true}}}}`,
		expectedEtcdPath: "openshift.io/buildconfigs/etcdstoragepathtestnamespace/bc1",
	},

	// used for streaming build logs from pod, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "buildlogs"}:         {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "buildlogoptionses"}: {ephemeral: true},

	// BuildGenerator helpers not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "buildrequests"}:               {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "binarybuildrequestoptionses"}: {ephemeral: true},
	// --

	// github.com/openshift/origin/pkg/deploy/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "deploymentconfigs"}: {
		stub:             `{"metadata": {"name": "dc1"}, "spec": {"selector": {"d": "c"}, "template": {"metadata": {"labels": {"d": "c"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container2"}]}}}}`,
		expectedEtcdPath: "openshift.io/deploymentconfigs/etcdstoragepathtestnamespace/dc1",
	},

	// used for streaming deployment logs from pod, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "deploymentlogs"}:         {ephemeral: true},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "deploymentlogoptionses"}: {ephemeral: true},

	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "deploymentrequests"}:        {ephemeral: true}, // triggers new dc, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "deploymentconfigrollbacks"}: {ephemeral: true}, // triggers rolleback dc, not stored in etcd
	// --

	// github.com/openshift/origin/pkg/image/api/docker10
	unversioned.GroupVersionResource{Group: "", Version: "1.0", Resource: "dockerimages"}: {ephemeral: true}, // part of imageapiv1.Image
	// --

	// github.com/openshift/origin/pkg/image/api/dockerpre012
	unversioned.GroupVersionResource{Group: "", Version: "pre012", Resource: "dockerimages"}: {ephemeral: true}, // part of imageapiv1.Image
	// --

	// github.com/openshift/origin/pkg/image/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagestreams"}: {
		stub:             `{"metadata": {"name": "is1"}, "spec": {"dockerImageRepository": "docker"}}`,
		expectedEtcdPath: "openshift.io/imagestreams/etcdstoragepathtestnamespace/is1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "images"}: {
		stub:             `{"dockerImageReference": "fedora:latest", "metadata": {"name": "image1"}}`,
		expectedEtcdPath: "openshift.io/images/image1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagestreamtags"}:     {ephemeral: true}, // part of image stream
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagesignatures"}:     {ephemeral: true}, // part of image
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagestreamimports"}:  {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagestreamimages"}:   {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "imagestreammappings"}: {ephemeral: true}, // not stored in etcd
	// --

	// github.com/openshift/origin/pkg/oauth/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthclientauthorizations"}: {
		stub:             `{"clientName": "system:serviceaccount:etcdstoragepathtestnamespace:client", "scopes": ["user:info"], "userName": "user", "userUID": "cannot be empty"}`,
		expectedEtcdPath: "openshift.io/oauth/clientauthorizations/user:system:serviceaccount:etcdstoragepathtestnamespace:client",
		prerequisites: []prerequisite{
			{
				gvr:  unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"},
				stub: `{"metadata": {"annotations": {"serviceaccounts.openshift.io/oauth-redirecturi.foo": "http://bar"}, "name": "client"}}`,
			},
			{
				gvr:  unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"},
				stub: `{"metadata": {"annotations": {"kubernetes.io/service-account.name": "client"}, "generateName": "client"}, "type": "kubernetes.io/service-account-token"}`,
			},
		},
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthaccesstokens"}: {
		stub:             `{"clientName": "client1", "metadata": {"name": "tokenneedstobelongenoughelseitwontwork"}, "userName": "user", "userUID": "cannot be empty"}`,
		expectedEtcdPath: "openshift.io/oauth/accesstokens/tokenneedstobelongenoughelseitwontwork",
		prerequisites: []prerequisite{
			{
				gvr:  unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthclients"},
				stub: `{"metadata": {"name": "client1"}}`,
			},
		},
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthauthorizetokens"}: {
		stub:             `{"clientName": "client0", "metadata": {"name": "tokenneedstobelongenoughelseitwontwork"}, "userName": "user", "userUID": "cannot be empty"}`,
		expectedEtcdPath: "openshift.io/oauth/authorizetokens/tokenneedstobelongenoughelseitwontwork",
		prerequisites: []prerequisite{
			{
				gvr:  unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthclients"},
				stub: `{"metadata": {"name": "client0"}}`,
			},
		},
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthclients"}: {
		stub:             `{"metadata": {"name": "client"}}`,
		expectedEtcdPath: "openshift.io/oauth/clients/client",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "oauthredirectreferences"}: {ephemeral: true}, // Used for specifying redirects, never stored in etcd
	// --

	// github.com/openshift/origin/pkg/project/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "projects"}:        {ephemeral: true}, // proxy for namespace so cannot test here
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "projectrequests"}: {ephemeral: true}, // not stored in etcd
	// --

	// github.com/openshift/origin/pkg/quota/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusterresourcequotas"}: {
		stub:             `{"metadata": {"name": "quota1"}, "spec": {"selector": {"labels": {"matchLabels": {"a": "b"}}}}}`,
		expectedEtcdPath: "openshift.io/clusterresourcequotas/quota1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "appliedclusterresourcequotas"}: {ephemeral: true}, // mirror of ClusterResourceQuota that cannot be created
	// --

	// github.com/openshift/origin/pkg/route/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "routes"}: {
		stub:             `{"metadata": {"name": "route1"}, "spec": {"host": "hostname1", "to": {"name": "service1"}}}`,
		expectedEtcdPath: "openshift.io/routes/etcdstoragepathtestnamespace/route1",
	},
	// --

	// github.com/openshift/origin/pkg/sdn/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "netnamespaces"}: { // This will fail to delete because meta.name != NetName but it is keyed off NetName
		stub:             `{"metadata": {"name": "nn1"}, "netid": 100, "netname": "networkname"}`,
		expectedEtcdPath: "openshift.io/registry/sdnnetnamespaces/networkname",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "hostsubnets"}: { // This will fail to delete because meta.name != Host but it is keyed off Host
		stub:             `{"host": "hostname", "hostIP": "192.168.1.1", "metadata": {"name": "hs1"}, "subnet": "192.168.1.1/24"}`,
		expectedEtcdPath: "openshift.io/registry/sdnsubnets/hostname",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "clusternetworks"}: {
		stub:             `{"metadata": {"name": "cn1"}, "network": "192.168.0.1/24", "serviceNetwork": "192.168.1.1/24"}`,
		expectedEtcdPath: "openshift.io/registry/sdnnetworks/cn1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "egressnetworkpolicies"}: {
		stub:             `{"metadata": {"name": "enp1"}, "spec": {"egress": [{"to": {"cidrSelector": "192.168.1.1/24"}, "type": "Allow"}]}}`,
		expectedEtcdPath: "openshift.io/registry/egressnetworkpolicy/etcdstoragepathtestnamespace/enp1",
	},
	// --

	// github.com/openshift/origin/pkg/security/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "podsecuritypolicyselfsubjectreviews"}: {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "podsecuritypolicyreviews"}:            {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "podsecuritypolicysubjectreviews"}:     {ephemeral: true}, // not stored in etcd
	// --

	// github.com/openshift/origin/pkg/template/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "templateconfigs"}: {
		stub:             `{"message": "Jenkins template", "metadata": {"name": "template1"}}`,
		expectedEtcdPath: "openshift.io/templates/etcdstoragepathtestnamespace/template1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "processedtemplates"}: {
		stub:             `{"message": "Jenkins template", "metadata": {"name": "template1"}}`,
		expectedEtcdPath: "openshift.io/templates/etcdstoragepathtestnamespace/template1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "templates"}: {
		stub:             `{"message": "Jenkins template", "metadata": {"name": "template1"}}`,
		expectedEtcdPath: "openshift.io/templates/etcdstoragepathtestnamespace/template1",
	},
	// --

	// github.com/openshift/origin/pkg/user/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "groups"}: {
		stub:             `{"metadata": {"name": "group"}, "users": ["user1", "user2"]}`,
		expectedEtcdPath: "openshift.io/groups/group",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "users"}: {
		stub:             `{"fullName": "user1", "metadata": {"name": "user1"}}`,
		expectedEtcdPath: "openshift.io/users/user1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "identities"}: {
		stub:             `{"metadata": {"name": "github:user2"}, "providerName": "github", "providerUserName": "user2"}`,
		expectedEtcdPath: "openshift.io/useridentities/github:user2",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "useridentitymappings"}: {ephemeral: true}, // pointer from user to identity, not stored in etcd
	// --

	// k8s.io/kubernetes/federation/apis/federation/v1beta1
	unversioned.GroupVersionResource{Group: "federation", Version: "v1beta1", Resource: "clusters"}: {ephemeral: true}, // we cannot create this  // TODO but we should be able to create it in kube
	// --

	// k8s.io/kubernetes/pkg/api/unversioned
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "statuses"}:      {ephemeral: true}, // return value for calls, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "apigroups"}:     {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "apiversionses"}: {ephemeral: true}, // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/api/v1
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}: {
		stub:             `{"data": {"foo": "bar"}, "metadata": {"name": "cm1"}}`,
		expectedEtcdPath: "kubernetes.io/configmaps/etcdstoragepathtestnamespace/cm1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}: {
		stub:             `{"metadata": {"name": "service1"}, "spec": {"externalName": "service1name", "ports": [{"port": 10000, "targetPort": 11000}], "selector": {"test": "data"}}}`,
		expectedEtcdPath: "kubernetes.io/services/specs/etcdstoragepathtestnamespace/service1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "podtemplates"}: {
		stub:             `{"metadata": {"name": "pt1name"}, "template": {"metadata": {"labels": {"pt": "01"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container9"}]}}}`,
		expectedEtcdPath: "kubernetes.io/podtemplates/etcdstoragepathtestnamespace/pt1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}: {
		stub:             `{"metadata": {"name": "pod1"}, "spec": {"containers": [{"image": "fedora:latest", "name": "container7"}]}}`,
		expectedEtcdPath: "kubernetes.io/pods/etcdstoragepathtestnamespace/pod1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "endpoints"}: {
		stub:             `{"metadata": {"name": "ep1name"}, "subsets": [{"addresses": [{"hostname": "bar-001", "ip": "192.168.3.1"}], "ports": [{"port": 8000}]}]}`,
		expectedEtcdPath: "kubernetes.io/services/endpoints/etcdstoragepathtestnamespace/ep1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "resourcequotas"}: {
		stub:             `{"metadata": {"name": "rq1name"}, "spec": {"hard": {"cpu": "5M"}}}`,
		expectedEtcdPath: "kubernetes.io/resourcequotas/etcdstoragepathtestnamespace/rq1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "limitranges"}: {
		stub:             `{"metadata": {"name": "lr1name"}, "spec": {"limits": [{"type": "Pod"}]}}`,
		expectedEtcdPath: "kubernetes.io/limitranges/etcdstoragepathtestnamespace/lr1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}: {
		stub:             `{"metadata": {"name": "namespace1"}, "spec": {"finalizers": ["kubernetes"]}}`,
		expectedEtcdPath: "kubernetes.io/namespaces/namespace1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "securitycontextconstraints"}: {
		stub:             `{"allowPrivilegedContainer": true, "fsGroup": {"type": "RunAsAny"}, "metadata": {"name": "scc1"}, "runAsUser": {"type": "RunAsAny"}, "seLinuxContext": {"type": "MustRunAs"}, "supplementalGroups": {"type": "RunAsAny"}}`,
		expectedEtcdPath: "kubernetes.io/securitycontextconstraints/scc1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}: {
		stub:             `{"metadata": {"name": "node1"}, "spec": {"unschedulable": true}}`,
		expectedEtcdPath: "kubernetes.io/minions/node1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumes"}: {
		stub:             `{"metadata": {"name": "pv1name"}, "spec": {"accessModes": ["ReadWriteOnce"], "capacity": {"storage": "3M"}, "hostPath": {"path": "/tmp/test/"}}}`,
		expectedEtcdPath: "kubernetes.io/persistentvolumes/pv1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "events"}: {
		stub:             `{"involvedObject": {"namespace": "etcdstoragepathtestnamespace"}, "message": "some data here", "metadata": {"name": "event1"}}`,
		expectedEtcdPath: "kubernetes.io/events/etcdstoragepathtestnamespace/event1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}: {
		stub:             `{"metadata": {"name": "pvc1"}, "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"limits": {"storage": "1M"}, "requests": {"storage": "2M"}}, "selector": {"matchLabels": {"pvc": "stuff"}}}}`,
		expectedEtcdPath: "kubernetes.io/persistentvolumeclaims/etcdstoragepathtestnamespace/pvc1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}: {
		stub:             `{"metadata": {"name": "sa1name"}, "secrets": [{"name": "secret00"}]}`,
		expectedEtcdPath: "kubernetes.io/serviceaccounts/etcdstoragepathtestnamespace/sa1name",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}: {
		stub:             `{"data": {"key": "ZGF0YSBmaWxl"}, "metadata": {"name": "secret1"}}`,
		expectedEtcdPath: "kubernetes.io/secrets/etcdstoragepathtestnamespace/secret1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "replicationcontrollers"}: {
		stub:             `{"metadata": {"name": "rc1"}, "spec": {"selector": {"new": "stuff"}, "template": {"metadata": {"labels": {"new": "stuff"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container8"}]}}}}`,
		expectedEtcdPath: "kubernetes.io/controllers/etcdstoragepathtestnamespace/rc1",
	},
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "exportoptionses"}:      {ephemeral: true}, // used in queries, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "bindings"}:             {ephemeral: true}, // annotation on pod, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "rangeallocations"}:     {ephemeral: true}, // stored in various places in etcd but cannot be directly created // TODO maybe possible in kube
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "componentstatuses"}:    {ephemeral: true}, // status info not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "serializedreferences"}: {ephemeral: true}, // used for serilization, not stored in etcd
	unversioned.GroupVersionResource{Group: "", Version: "v1", Resource: "podstatusresults"}:     {ephemeral: true}, // wrapper object not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/apps/v1beta1
	unversioned.GroupVersionResource{Group: "apps", Version: "v1beta1", Resource: "statefulsets"}: {
		stub:             `{"metadata": {"name": "ss1"}, "spec": {"template": {"metadata": {"labels": {"a": "b"}}}}}`,
		expectedEtcdPath: "kubernetes.io/statefulsets/etcdstoragepathtestnamespace/ss1",
	},
	// --

	// k8s.io/kubernetes/pkg/apis/authentication/v1beta1
	unversioned.GroupVersionResource{Group: "authentication.k8s.io", Version: "v1beta1", Resource: "tokenreviews"}: {ephemeral: true}, // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/authorization/v1beta1

	// SAR objects that are not stored in etcd
	unversioned.GroupVersionResource{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "selfsubjectaccessreviews"}:  {ephemeral: true},
	unversioned.GroupVersionResource{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "localsubjectaccessreviews"}: {ephemeral: true},
	unversioned.GroupVersionResource{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "subjectaccessreviews"}:      {ephemeral: true},
	// --

	// k8s.io/kubernetes/pkg/apis/autoscaling/v1
	unversioned.GroupVersionResource{Group: "autoscaling", Version: "v1", Resource: "horizontalpodautoscalers"}: {ephemeral: true}, // creating this returns a apisextensionsv1beta1.HorizontalPodAutoscaler so test that instead
	unversioned.GroupVersionResource{Group: "autoscaling", Version: "v1", Resource: "scales"}:                   {ephemeral: true}, // not stored in etcd, part of kapiv1.ReplicationController
	// --

	// k8s.io/kubernetes/pkg/apis/batch/v1
	unversioned.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}: {
		stub:             `{"metadata": {"name": "job1"}, "spec": {"manualSelector": true, "selector": {"matchLabels": {"controller-uid": "uid1"}}, "template": {"metadata": {"labels": {"controller-uid": "uid1"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container1"}], "dnsPolicy": "ClusterFirst", "restartPolicy": "Never"}}}}`,
		expectedEtcdPath: "kubernetes.io/jobs/etcdstoragepathtestnamespace/job1",
	},
	// --

	// k8s.io/kubernetes/pkg/apis/batch/v2alpha1
	unversioned.GroupVersionResource{Group: "batch", Version: "v2alpha1", Resource: "scheduledjobs"}: {
		stub:             `{"metadata": {"name": "cj1"}, "spec": {"jobTemplate": {"spec": {"template": {"metadata": {"labels": {"controller-uid": "uid0"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container0"}], "dnsPolicy": "ClusterFirst", "restartPolicy": "Never"}}}}, "schedule": "* * * * *"}}`,
		expectedEtcdPath: "kubernetes.io/cronjobs/etcdstoragepathtestnamespace/cj1",
	},
	unversioned.GroupVersionResource{Group: "batch", Version: "v2alpha1", Resource: "cronjobs"}: {
		stub:             `{"metadata": {"name": "cj1"}, "spec": {"jobTemplate": {"spec": {"template": {"metadata": {"labels": {"controller-uid": "uid0"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container0"}], "dnsPolicy": "ClusterFirst", "restartPolicy": "Never"}}}}, "schedule": "* * * * *"}}`,
		expectedEtcdPath: "kubernetes.io/cronjobs/etcdstoragepathtestnamespace/cj1",
	},
	unversioned.GroupVersionResource{Group: "batch", Version: "v2alpha1", Resource: "jobs"}:         {ephemeral: true}, // creating this makes a apisbatchv1.Job so test that instead
	unversioned.GroupVersionResource{Group: "batch", Version: "v2alpha1", Resource: "jobtemplates"}: {ephemeral: true}, // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/certificates/v1alpha1
	unversioned.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1alpha1", Resource: "certificatesigningrequests"}: {
		stub:             `{"metadata": {"name": "csr1"}, "spec": {"request": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQnlqQ0NBVE1DQVFBd2dZa3hDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJRXdwRFlXeHBabTl5Ym1saApNUll3RkFZRFZRUUhFdzFOYjNWdWRHRnBiaUJXYVdWM01STXdFUVlEVlFRS0V3cEhiMjluYkdVZ1NXNWpNUjh3CkhRWURWUVFMRXhaSmJtWnZjbTFoZEdsdmJpQlVaV05vYm05c2IyZDVNUmN3RlFZRFZRUURFdzUzZDNjdVoyOXYKWjJ4bExtTnZiVENCbnpBTkJna3Foa2lHOXcwQkFRRUZBQU9CalFBd2dZa0NnWUVBcFp0WUpDSEo0VnBWWEhmVgpJbHN0UVRsTzRxQzAzaGpYK1prUHl2ZFlkMVE0K3FiQWVUd1htQ1VLWUhUaFZSZDVhWFNxbFB6eUlCd2llTVpyCldGbFJRZGRaMUl6WEFsVlJEV3dBbzYwS2VjcWVBWG5uVUsrNWZYb1RJL1VnV3NocmU4dEoreC9UTUhhUUtSL0oKY0lXUGhxYVFoc0p1elpidkFkR0E4MEJMeGRNQ0F3RUFBYUFBTUEwR0NTcUdTSWIzRFFFQkJRVUFBNEdCQUlobAo0UHZGcStlN2lwQVJnSTVaTStHWng2bXBDejQ0RFRvMEprd2ZSRGYrQnRyc2FDMHE2OGVUZjJYaFlPc3E0ZmtIClEwdUEwYVZvZzNmNWlKeENhM0hwNWd4YkpRNnpWNmtKMFRFc3VhYU9oRWtvOXNkcENvUE9uUkJtMmkvWFJEMkQKNmlOaDhmOHowU2hHc0ZxakRnRkh5RjNvK2xVeWorVUM2SDFRVzdibgotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0="}}`,
		expectedEtcdPath: "kubernetes.io/certificatesigningrequests/csr1",
	},
	// --

	// k8s.io/kubernetes/pkg/apis/componentconfig/v1alpha1
	unversioned.GroupVersionResource{Group: "componentconfig", Version: "v1alpha1", Resource: "kubeletconfigurations"}:       {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "componentconfig", Version: "v1alpha1", Resource: "kubeschedulerconfigurations"}: {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "componentconfig", Version: "v1alpha1", Resource: "kubeproxyconfigurations"}:     {ephemeral: true}, // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/extensions/v1beta1
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "daemonsets"}: {
		stub:             `{"metadata": {"name": "ds1"}, "spec": {"selector": {"matchLabels": {"u": "t"}}, "template": {"metadata": {"labels": {"u": "t"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container5"}]}}}}`,
		expectedEtcdPath: "kubernetes.io/daemonsets/etcdstoragepathtestnamespace/ds1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "podsecuritypolicies"}: {
		stub:             `{"metadata": {"name": "psp1"}, "spec": {"fsGroup": {"rule": "RunAsAny"}, "privileged": true, "runAsUser": {"rule": "RunAsAny"}, "seLinux": {"rule": "MustRunAs"}, "supplementalGroups": {"rule": "RunAsAny"}}}`,
		expectedEtcdPath: "kubernetes.io/podsecuritypolicy/psp1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "thirdpartyresources"}: {
		stub:             `{"description": "third party", "metadata": {"name": "kind.domain.tld"}, "versions": [{"name": "v3"}]}`,
		expectedEtcdPath: "kubernetes.io/thirdpartyresources/kind.domain.tld",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "ingresses"}: {
		stub:             `{"metadata": {"name": "ingress1"}, "spec": {"backend": {"serviceName": "service", "servicePort": 5000}}}`,
		expectedEtcdPath: "kubernetes.io/ingress/etcdstoragepathtestnamespace/ingress1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "networkpolicies"}: {
		stub:             `{"metadata": {"name": "np1"}, "spec": {"podSelector": {"matchLabels": {"e": "f"}}}}`,
		expectedEtcdPath: "kubernetes.io/networkpolicies/etcdstoragepathtestnamespace/np1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "deployments"}: {
		stub:             `{"metadata": {"name": "deployment1"}, "spec": {"selector": {"matchLabels": {"f": "z"}}, "template": {"metadata": {"labels": {"f": "z"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container6"}]}}}}`,
		expectedEtcdPath: "kubernetes.io/deployments/etcdstoragepathtestnamespace/deployment1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "horizontalpodautoscalers"}: {
		stub:             `{"metadata": {"name": "hpa1"}, "spec": {"maxReplicas": 3, "scaleRef": {"kind": "something", "name": "cross"}}}`,
		expectedEtcdPath: "kubernetes.io/horizontalpodautoscalers/etcdstoragepathtestnamespace/hpa1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "replicasets"}: {
		stub:             `{"metadata": {"name": "rs1"}, "spec": {"selector": {"matchLabels": {"g": "h"}}, "template": {"metadata": {"labels": {"g": "h"}}, "spec": {"containers": [{"image": "fedora:latest", "name": "container4"}]}}}}`,
		expectedEtcdPath: "kubernetes.io/replicasets/etcdstoragepathtestnamespace/rs1",
	},
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "deploymentrollbacks"}:          {ephemeral: true}, // used to rollback deployment, not stored in etcd
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "replicationcontrollerdummies"}: {ephemeral: true}, // not stored in etcd
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "jobs"}:                         {ephemeral: true}, // creating this makes a apisbatchv1.Job so test that instead
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "scales"}:                       {ephemeral: true}, // not stored in etcd, part of kapiv1.ReplicationController
	unversioned.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "thirdpartyresourcedatas"}:      {ephemeral: true}, // we cannot create this  // TODO but we should be able to create it in kube
	// --

	// k8s.io/kubernetes/pkg/apis/imagepolicy/v1alpha1
	unversioned.GroupVersionResource{Group: "imagepolicy.k8s.io", Version: "v1alpha1", Resource: "imagereviews"}: {ephemeral: true}, // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/policy/v1beta1
	unversioned.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "poddisruptionbudgets"}: {
		stub:             `{"metadata": {"name": "pdb1"}, "spec": {"selector": {"matchLabels": {"anokkey": "anokvalue"}}}}`,
		expectedEtcdPath: "kubernetes.io/poddisruptionbudgets/etcdstoragepathtestnamespace/pdb1",
	},
	unversioned.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "evictions"}: {ephemeral: true}, // not stored in etcd, deals with evicting kapiv1.Pod
	// --

	// k8s.io/kubernetes/pkg/apis/rbac/v1alpha1

	// we cannot create these  // TODO but we should be able to create them in kube
	unversioned.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Resource: "roles"}:               {ephemeral: true},
	unversioned.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Resource: "clusterroles"}:        {ephemeral: true},
	unversioned.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Resource: "rolebindings"}:        {ephemeral: true},
	unversioned.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Resource: "clusterrolebindings"}: {ephemeral: true},
	// --

	// k8s.io/kubernetes/pkg/apis/storage/v1beta1
	unversioned.GroupVersionResource{Group: "storage.k8s.io", Version: "v1beta1", Resource: "storageclasses"}: {
		stub:             `{"metadata": {"name": "sc1"}, "provisioner": "aws"}`,
		expectedEtcdPath: "kubernetes.io/storageclasses/sc1",
	},
}

// Only add objects to this list when there is no mapping from GVK to GVR (and thus there is no way to create the object)
var gvkWhiteList = createGVKWhiteList(
	// k8s.io/kubernetes/pkg/api/v1
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "NodeProxyOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "PodAttachOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "PodExecOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "PodLogOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "PodProxyOptions"},
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "ServiceProxyOptions"},
	unversioned.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "authentication.k8s.io", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "authentication.k8s.io", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "authentication.k8s.io", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "authorization.k8s.io", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "authorization.k8s.io", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "authorization.k8s.io", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "autoscaling", Version: "v1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "autoscaling", Version: "v1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "autoscaling", Version: "v1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v2alpha1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v2alpha1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1alpha1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1alpha1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1alpha1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "federation", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "federation", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "federation", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "imagepolicy.k8s.io", Version: "v1alpha1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "imagepolicy.k8s.io", Version: "v1alpha1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "imagepolicy.k8s.io", Version: "v1alpha1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "policy", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "policy", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "policy", Version: "v1beta1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "ListOptions"},
	unversioned.GroupVersionKind{Group: "storage.k8s.io", Version: "v1beta1", Kind: "DeleteOptions"},
	unversioned.GroupVersionKind{Group: "storage.k8s.io", Version: "v1beta1", Kind: "ExportOptions"},
	unversioned.GroupVersionKind{Group: "storage.k8s.io", Version: "v1beta1", Kind: "ListOptions"},
	// --

	// k8s.io/kubernetes/pkg/watch/versioned
	unversioned.GroupVersionKind{Group: "", Version: "v1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "apps", Version: "v1beta1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "authorization.k8s.io", Version: "v1beta1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "autoscaling", Version: "v1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "batch", Version: "v2alpha1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "certificates.k8s.io", Version: "v1alpha1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "extensions", Version: "v1beta1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "federation", Version: "v1beta1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "policy", Version: "v1beta1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1alpha1", Kind: "WatchEvent"},
	unversioned.GroupVersionKind{Group: "storage.k8s.io", Version: "v1beta1", Kind: "WatchEvent"},
	// --
)

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
	mapper, _ := f.Object()

	clientConfig, err := loader.ClientConfig()
	if err != nil {
		t.Fatalf("error geting client config: %#v", err)
	}
	client, err := newClient(*clientConfig)
	if err != nil {
		t.Fatalf("error creating client: %#v", err)
	}

	if _, err := kubeClient.Core().Namespaces().Create(&kapi.Namespace{ObjectMeta: kapi.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatalf("error creating test namespace: %#v", err)
	}

	gvkSeen := map[unversioned.GroupVersionKind]empty{}
	gvrSeen := map[unversioned.GroupVersionResource]empty{}

	for gvk, apiType := range kapi.Scheme.AllKnownTypes() {
		// we do not care about internal objects or lists // TODO make sure this is always true
		if gvk.Version == runtime.APIVersionInternal || strings.HasSuffix(apiType.Name(), "List") {
			continue
		}

		kind := gvk.Kind
		pkgPath := apiType.PkgPath()

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			gvkSeen[gvk] = empty{}
			_, ok := gvkWhiteList[gvk]
			if ok {
				t.Logf("skipping test for %s from %s because its GVK %s is whitelisted and has no mapping", kind, pkgPath, gvk)
			} else {
				t.Errorf("no mapping found for %s from %s but its GVK %s is not whitelisted", kind, pkgPath, gvk)
			}
			continue
		}

		gvr := gvk.GroupVersion().WithResource(mapping.Resource)
		gvrSeen[gvr] = empty{}

		ptrType := reflect.PtrTo(apiType)
		testData, ok := etcdStorageData[gvr]

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

		if len(testData.expectedEtcdPath) == 0 || len(testData.stub) == 0 {
			t.Errorf("empty test data for %s from %s", kind, pkgPath)
			continue
		}

		obj, err := jsonToObject(testData.stub, gvk)
		if err != nil || reflect.TypeOf(obj) != ptrType || isZero(reflect.ValueOf(obj)) {
			t.Errorf("invalid test data for %s from %s: %s", kind, pkgPath, err)
			continue
		}

		func() { // forces defer to run per iteration of the for loop
			all := &[]cleanupData{}
			defer func() {
				if !t.Failed() { // do not cleanup if test has already failed since we may need things in the etcd dump
					if err := client.cleanup(all); err != nil {
						t.Fatalf("failed to clean up etcd: %#v", err)
					}
				}
			}()

			if err := client.createPrerequisites(mapper, testNamespace, testData.prerequisites, all); err != nil {
				t.Errorf("failed to create prerequisites for %s from %s: %#v", kind, pkgPath, err)
				return
			}

			if !isInCreateAndCompareWhiteList(obj) { // do not try to create whitelisted items
				if err := client.create(testData.stub, testNamespace, mapping, all); err != nil {
					t.Errorf("failed to create stub for %s from %s: %#v", kind, pkgPath, err)
					return
				}
			}

			output, err := getFromEtcd(keys, testData.expectedEtcdPath, gvk)
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

			if !kapi.Semantic.DeepDerivative(obj, output) {
				t.Errorf("Test stub for %s from %s does not match: %s", kind, pkgPath, diff.ObjectGoPrintDiff(obj, output))
			}
		}()
	}

	inEtcdData := diffMapKeys(etcdStorageData, gvrSeen, gvStringer)
	inGVRSeen := diffMapKeys(gvrSeen, etcdStorageData, gvStringer)
	if len(inEtcdData) != 0 || len(inGVRSeen) != 0 {
		t.Errorf("etcd data does not match the types we saw:\nin etcd data but not seen:\n%s\nseen but not in etcd data:\n%s", inEtcdData, inGVRSeen)
	}

	inGVKData := diffMapKeys(gvkWhiteList, gvkSeen, gvStringer)
	inGVKSeen := diffMapKeys(gvkSeen, gvkWhiteList, gvStringer)
	if len(inGVKData) != 0 || len(inGVKSeen) != 0 {
		t.Errorf("GVK whitelist data does not match the types we saw:\nin GVK whitelist but not seen:\n%s\nseen but not in GVK whitelist:\n%s", inGVKData, inGVKSeen)
	}
}

type prerequisite struct {
	gvr  unversioned.GroupVersionResource
	stub string
}

type empty struct{}

type cleanupData struct {
	obj     runtime.Object
	mapping *meta.RESTMapping
}

func createGVKWhiteList(gvks ...unversioned.GroupVersionKind) map[unversioned.GroupVersionKind]empty {
	whiteList := map[unversioned.GroupVersionKind]empty{}
	for _, gvk := range gvks {
		_, ok := whiteList[gvk]
		if ok {
			panic("invalid whitelist contains duplicate keys")
		}
		whiteList[gvk] = empty{}
	}
	return whiteList
}

func jsonToObject(stub string, gvk unversioned.GroupVersionKind) (runtime.Object, error) {
	obj, err := kapi.Scheme.New(gvk)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(stub), obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func gvStringer(i interface{}) string {
	base := "\n\t"
	switch gv := i.(type) {
	case unversioned.GroupVersionResource:
		return base + gv.String()
	case unversioned.GroupVersionKind:
		return base + gv.String()
	default:
		panic("unexpected type")
	}
}

type allClient struct {
	client  *http.Client
	config  *restclient.Config
	backoff restclient.BackoffManager
}

func (c *allClient) verb(verb string, gvk unversioned.GroupVersionKind) (*restclient.Request, error) {
	apiPath := "/apis"
	switch {
	case latest.OriginKind(gvk):
		apiPath = "/oapi"
	case gvk.Group == kapi.GroupName:
		apiPath = "/api"
	}
	baseURL, versionedAPIPath, err := restclient.DefaultServerURL(c.config.Host, apiPath, gvk.GroupVersion(), true)
	if err != nil {
		return nil, err
	}
	contentConfig := c.config.ContentConfig
	gv := gvk.GroupVersion()
	contentConfig.GroupVersion = &gv
	serializers, err := createSerializers(contentConfig)
	if err != nil {
		return nil, err
	}
	return restclient.NewRequest(c.client, verb, baseURL, versionedAPIPath, contentConfig, *serializers, c.backoff, c.config.RateLimiter), nil
}

func (c *allClient) create(stub, ns string, mapping *meta.RESTMapping, all *[]cleanupData) error {
	req, err := c.verb("POST", mapping.GroupVersionKind)
	if err != nil {
		return err
	}
	namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	output, err := req.NamespaceIfScoped(ns, namespaced).Resource(mapping.Resource).Body(strings.NewReader(stub)).Do().Get()
	if err != nil {
		return err
	}
	*all = append(*all, cleanupData{output, mapping})
	return nil
}

func (c *allClient) destroy(obj runtime.Object, mapping *meta.RESTMapping) error {
	req, err := c.verb("DELETE", mapping.GroupVersionKind)
	if err != nil {
		return err
	}
	namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	name, err := mapping.MetadataAccessor.Name(obj)
	if err != nil {
		return err
	}
	ns, err := mapping.MetadataAccessor.Namespace(obj)
	if err != nil {
		return err
	}
	return req.NamespaceIfScoped(ns, namespaced).Resource(mapping.Resource).Name(name).Do().Error()
}

func (c *allClient) cleanup(all *[]cleanupData) error {
	for i := len(*all) - 1; i >= 0; i-- { // delete in reverse order in case creation order mattered
		obj := (*all)[i].obj
		mapping := (*all)[i].mapping

		if err := c.destroy(obj, mapping); err != nil {
			if kubeerr.IsNotFound(err) && isInInvalidNameWhiteList(obj) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (c *allClient) createPrerequisites(mapper meta.RESTMapper, ns string, prerequisites []prerequisite, all *[]cleanupData) error {
	for _, prerequisite := range prerequisites {
		gvk, err := mapper.KindFor(prerequisite.gvr)
		if err != nil {
			return err
		}
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		if err := c.create(prerequisite.stub, ns, mapping, all); err != nil {
			return err
		}
	}
	return nil
}

func newClient(config restclient.Config) (*allClient, error) {
	config.ContentConfig.NegotiatedSerializer = kapi.Codecs
	config.ContentConfig.ContentType = "application/json"
	config.Timeout = 30 * time.Second
	config.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(3, 10)

	transport, err := restclient.TransportFor(&config)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	backoff := &restclient.URLBackoff{
		Backoff: flowcontrol.NewBackOff(1*time.Second, 10*time.Second),
	}

	return &allClient{
		client:  client,
		config:  &config,
		backoff: backoff,
	}, nil
}

// copied from restclient
func createSerializers(config restclient.ContentConfig) (*restclient.Serializers, error) {
	mediaTypes := config.NegotiatedSerializer.SupportedMediaTypes()
	contentType := config.ContentType
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("the content type specified in the client configuration is not recognized: %v", err)
	}
	info, ok := runtime.SerializerInfoForMediaType(mediaTypes, mediaType)
	if !ok {
		if len(contentType) != 0 || len(mediaTypes) == 0 {
			return nil, fmt.Errorf("no serializers registered for %s", contentType)
		}
		info = mediaTypes[0]
	}

	internalGV := unversioned.GroupVersions{
		{
			Group:   config.GroupVersion.Group,
			Version: runtime.APIVersionInternal,
		},
		// always include the legacy group as a decoding target to handle non-error `Status` return types
		{
			Group:   "",
			Version: runtime.APIVersionInternal,
		},
	}

	s := &restclient.Serializers{
		Encoder: config.NegotiatedSerializer.EncoderForVersion(info.Serializer, *config.GroupVersion),
		Decoder: config.NegotiatedSerializer.DecoderToVersion(info.Serializer, internalGV),

		RenegotiatedDecoder: func(contentType string, params map[string]string) (runtime.Decoder, error) {
			info, ok := runtime.SerializerInfoForMediaType(mediaTypes, contentType)
			if !ok {
				return nil, fmt.Errorf("serializer for %s not registered", contentType)
			}
			return config.NegotiatedSerializer.DecoderToVersion(info.Serializer, internalGV), nil
		},
	}
	if info.StreamSerializer != nil {
		s.StreamingSerializer = info.StreamSerializer.Serializer
		s.Framer = info.StreamSerializer.Framer
	}

	return s, nil
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

func getFromEtcd(keys etcd.KeysAPI, path string, gvk unversioned.GroupVersionKind) (runtime.Object, error) {
	response, err := keys.Get(context.Background(), path, nil)
	if err != nil {
		return nil, err
	}
	output, err := jsonToObject(response.Node.Value, gvk)
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

func diffMapKeys(a, b interface{}, stringer func(interface{}) string) []string {
	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	ret := []string{}

	for _, ka := range av.MapKeys() {
		kat := ka.Interface()
		found := false
		for _, kb := range bv.MapKeys() {
			kbt := kb.Interface()
			if kat == kbt {
				found = true
				break
			}
		}
		if !found {
			ret = append(ret, stringer(kat))
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
