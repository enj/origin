/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	cacheddiscovery "k8s.io/client-go/discovery/cached"
	clientset "k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/kubernetes/cmd/kube-apiserver/app"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/test/integration"
	"k8s.io/kubernetes/test/integration/framework"

	// install all APIs
	_ "k8s.io/kubernetes/pkg/master" // TODO what else is needed

	"github.com/coreos/etcd/clientv3"
	"k8s.io/client-go/restmapper"
)

// Be very careful when whitelisting an object as ephemeral.
// Doing so removes the safety we gain from this test by skipping that object.
var ephemeralWhiteList = createEphemeralWhiteList(

	// k8s.io/kubernetes/pkg/api/v1
	gvk("", "v1", "Binding"),             // annotation on pod, not stored in etcd
	gvk("", "v1", "RangeAllocation"),     // stored in various places in etcd but cannot be directly created
	gvk("", "v1", "ComponentStatus"),     // status info not stored in etcd
	gvk("", "v1", "SerializedReference"), // used for serilization, not stored in etcd
	gvk("", "v1", "PodStatusResult"),     // wrapper object not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/authentication/v1beta1
	gvk("authentication.k8s.io", "v1beta1", "TokenReview"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/authentication/v1
	gvk("authentication.k8s.io", "v1", "TokenReview"),  // not stored in etcd
	gvk("authentication.k8s.io", "v1", "TokenRequest"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/authorization/v1beta1

	// SRR objects that are not stored in etcd
	gvk("authorization.k8s.io", "v1beta1", "SelfSubjectRulesReview"),
	// SAR objects that are not stored in etcd
	gvk("authorization.k8s.io", "v1beta1", "SelfSubjectAccessReview"),
	gvk("authorization.k8s.io", "v1beta1", "LocalSubjectAccessReview"),
	gvk("authorization.k8s.io", "v1beta1", "SubjectAccessReview"),
	// --

	// k8s.io/kubernetes/pkg/apis/authorization/v1

	// SRR objects that are not stored in etcd
	gvk("authorization.k8s.io", "v1", "SelfSubjectRulesReview"),
	// SAR objects that are not stored in etcd
	gvk("authorization.k8s.io", "v1", "SelfSubjectAccessReview"),
	gvk("authorization.k8s.io", "v1", "LocalSubjectAccessReview"),
	gvk("authorization.k8s.io", "v1", "SubjectAccessReview"),
	// --

	// k8s.io/kubernetes/pkg/apis/autoscaling/v1
	gvk("autoscaling", "v1", "Scale"), // not stored in etcd, part of kapiv1.ReplicationController
	// --

	// k8s.io/kubernetes/pkg/apis/apps/v1beta1
	gvk("apps", "v1beta1", "Scale"),              // not stored in etcd, part of kapiv1.ReplicationController
	gvk("apps", "v1beta1", "DeploymentRollback"), // used to rollback deployment, not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/apps/v1beta2
	gvk("apps", "v1beta2", "Scale"), // not stored in etcd, part of kapiv1.ReplicationController
	// --

	// k8s.io/kubernetes/pkg/apis/batch/v1beta1
	gvk("batch", "v1beta1", "JobTemplate"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/batch/v2alpha1
	gvk("batch", "v2alpha1", "JobTemplate"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/componentconfig/v1alpha1
	gvk("componentconfig", "v1alpha1", "KubeSchedulerConfiguration"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/extensions/v1beta1
	gvk("extensions", "v1beta1", "DeploymentRollback"),         // used to rollback deployment, not stored in etcd
	gvk("extensions", "v1beta1", "ReplicationControllerDummy"), // not stored in etcd
	gvk("extensions", "v1beta1", "Scale"),                      // not stored in etcd, part of kapiv1.ReplicationController
	// --

	// k8s.io/kubernetes/pkg/apis/imagepolicy/v1alpha1
	gvk("imagepolicy.k8s.io", "v1alpha1", "ImageReview"), // not stored in etcd
	// --

	// k8s.io/kubernetes/pkg/apis/policy/v1beta1
	gvk("policy", "v1beta1", "Eviction"), // not stored in etcd, deals with evicting kapiv1.Pod
	// --

	// k8s.io/kubernetes/pkg/apis/admission/v1beta1
	gvk("admission.k8s.io", "v1beta1", "AdmissionReview"), // not stored in etcd, call out to webhooks.
	// --
)

// Only add kinds to this list when there is no way to create the object
var kindWhiteList = sets.NewString(
	// k8s.io/kubernetes/pkg/api/v1
	"DeleteOptions",
	"ExportOptions",
	"ListOptions",
	"NodeProxyOptions",
	"PodAttachOptions",
	"PodExecOptions",
	"PodLogOptions",
	"PodProxyOptions",
	"ServiceProxyOptions",
	"GetOptions",
	"APIGroup",
	"PodPortForwardOptions",
	"APIVersions",
	// --

	// k8s.io/kubernetes/pkg/watch/versioned
	"WatchEvent",
	// --

	// k8s.io/apimachinery/pkg/apis/meta/v1
	"Status",
	// --
)

// namespace used for all tests, do not change this
const testNamespace = "etcdstoragepathtestnamespace"

// TestEtcdStoragePath tests to make sure that all objects are stored in an expected location in etcd.
// It will start failing when a new type is added to ensure that all future types are added to this test.
// It will also fail when a type gets moved to a different location. Be very careful in this situation because
// it essentially means that you will be break old clusters unless you create some migration path for the old data.
func TestEtcdStoragePath(t *testing.T) {
	certDir, _ := ioutil.TempDir("", "test-integration-etcd")
	defer os.RemoveAll(certDir)

	client, kvClient, mapper := startRealMasterOrDie(t, certDir)
	defer func() {
		dumpEtcdKVOnFailure(t, kvClient)
	}()

	etcdStorageData := GetEtcdStorageData()

	kindSeen := sets.NewString()
	pathSeen := map[string][]schema.GroupVersionResource{}
	etcdSeen := map[schema.GroupVersionResource]empty{}
	ephemeralSeen := map[schema.GroupVersionKind]empty{}
	cohabitatingResources := map[string]map[schema.GroupVersionKind]empty{}

	for gvk, apiType := range legacyscheme.Scheme.AllKnownTypes() {
		// we do not care about internal objects or lists // TODO make sure this is always true
		if gvk.Version == runtime.APIVersionInternal || strings.HasSuffix(apiType.Name(), "List") {
			continue
		}

		kind := gvk.Kind
		pkgPath := apiType.PkgPath()

		if kindWhiteList.Has(kind) {
			kindSeen.Insert(kind)
			continue
		}
		_, isEphemeral := ephemeralWhiteList[gvk]
		if isEphemeral {
			ephemeralSeen[gvk] = empty{}
			continue
		}

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			t.Errorf("unexpected error getting mapping for %s from %s with GVK %s: %v", kind, pkgPath, gvk, err)
			continue
		}

		etcdSeen[mapping.Resource] = empty{}

		testData, hasTest := etcdStorageData[mapping.Resource]

		if !hasTest {
			t.Errorf("no test data for %s from %s.  Please add a test for your new type to etcdStorageData.", kind, pkgPath)
			continue
		}

		if len(testData.ExpectedEtcdPath) == 0 {
			t.Errorf("empty test data for %s from %s", kind, pkgPath)
			continue
		}

		shouldCreate := len(testData.Stub) != 0 // try to create only if we have a stub

		var input *metaObject
		if shouldCreate {
			if input, err = jsonToMetaObject([]byte(testData.Stub)); err != nil || input.isEmpty() {
				t.Errorf("invalid test data for %s from %s: %v", kind, pkgPath, err)
				continue
			}
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

			if err := client.createPrerequisites(mapper, testNamespace, testData.Prerequisites, all); err != nil {
				t.Errorf("failed to create prerequisites for %s from %s: %#v", kind, pkgPath, err)
				return
			}

			if shouldCreate { // do not try to create items with no stub
				if err := client.create(testData.Stub, testNamespace, mapping, all); err != nil {
					t.Errorf("failed to create stub for %s from %s: %#v", kind, pkgPath, err)
					return
				}
			}

			output, err := getFromEtcd(kvClient, testData.ExpectedEtcdPath)
			if err != nil {
				t.Errorf("failed to get from etcd for %s from %s: %#v", kind, pkgPath, err)
				return
			}

			expectedGVK := gvk
			if testData.ExpectedGVK != nil {
				if gvk == *testData.ExpectedGVK {
					t.Errorf("GVK override %s for %s from %s is unnecessary or something was changed incorrectly", testData.ExpectedGVK, kind, pkgPath)
				}
				expectedGVK = *testData.ExpectedGVK
			}

			actualGVK := output.getGVK()
			if actualGVK != expectedGVK {
				t.Errorf("GVK for %s from %s does not match, expected %s got %s", kind, pkgPath, expectedGVK, actualGVK)
			}

			if !apiequality.Semantic.DeepDerivative(input, output) {
				t.Errorf("Test stub for %s from %s does not match: %s", kind, pkgPath, diff.ObjectGoPrintDiff(input, output))
			}

			addGVKToEtcdBucket(cohabitatingResources, actualGVK, getEtcdBucket(testData.ExpectedEtcdPath))
			pathSeen[testData.ExpectedEtcdPath] = append(pathSeen[testData.ExpectedEtcdPath], mapping.Resource)
		}()
	}

	if inEtcdData, inEtcdSeen := diffMaps(etcdStorageData, etcdSeen); len(inEtcdData) != 0 || len(inEtcdSeen) != 0 {
		t.Errorf("etcd data does not match the types we saw:\nin etcd data but not seen:\n%s\nseen but not in etcd data:\n%s", inEtcdData, inEtcdSeen)
	}

	if inEphemeralWhiteList, inEphemeralSeen := diffMaps(ephemeralWhiteList, ephemeralSeen); len(inEphemeralWhiteList) != 0 || len(inEphemeralSeen) != 0 {
		t.Errorf("ephemeral whitelist does not match the types we saw:\nin ephemeral whitelist but not seen:\n%s\nseen but not in ephemeral whitelist:\n%s", inEphemeralWhiteList, inEphemeralSeen)
	}

	if inKindData, inKindSeen := diffMaps(kindWhiteList, kindSeen); len(inKindData) != 0 || len(inKindSeen) != 0 {
		t.Errorf("kind whitelist data does not match the types we saw:\nin kind whitelist but not seen:\n%s\nseen but not in kind whitelist:\n%s", inKindData, inKindSeen)
	}

	for bucket, gvks := range cohabitatingResources {
		if len(gvks) != 1 {
			gvkStrings := []string{}
			for key := range gvks {
				gvkStrings = append(gvkStrings, keyStringer(key))
			}
			t.Errorf("cohabitating resources in etcd bucket %s have inconsistent GVKs\nyou may need to use DefaultStorageFactory.AddCohabitatingResources to sync the GVK of these resources:\n%s", bucket, gvkStrings)
		}
	}

	for path, gvrs := range pathSeen {
		if len(gvrs) != 1 {
			gvrStrings := []string{}
			for _, key := range gvrs {
				gvrStrings = append(gvrStrings, keyStringer(key))
			}
			t.Errorf("invalid test data, please ensure all expectedEtcdPath are unique, path %s has duplicate GVRs:\n%s", path, gvrStrings)
		}
	}
}

func startRealMasterOrDie(t *testing.T, certDir string) (*allClient, clientv3.KV, meta.RESTMapper) {
	_, defaultServiceClusterIPRange, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	kubeClientConfigValue := atomic.Value{}
	storageConfigValue := atomic.Value{}

	go func() {
		// Catch panics that occur in this go routine so we get a comprehensible failure
		defer func() {
			if err := recover(); err != nil {
				t.Errorf("Unexpected panic trying to start API master: %#v", err)
			}
		}()

		listener, _, err := genericapiserveroptions.CreateListener("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		kubeAPIServerOptions := options.NewServerRunOptions()
		kubeAPIServerOptions.SecureServing.Listener = listener
		kubeAPIServerOptions.SecureServing.ServerCert.CertDirectory = certDir
		kubeAPIServerOptions.Etcd.StorageConfig.ServerList = []string{framework.GetEtcdURL()}
		kubeAPIServerOptions.Etcd.DefaultStorageMediaType = runtime.ContentTypeJSON // TODO use protobuf?
		kubeAPIServerOptions.ServiceClusterIPRange = *defaultServiceClusterIPRange
		kubeAPIServerOptions.Authorization.Modes = []string{"RBAC"}
		kubeAPIServerOptions.Admission.GenericAdmission.DisablePlugins = []string{"ServiceAccount"}
		completedOptions, err := app.Complete(kubeAPIServerOptions)
		if err != nil {
			t.Fatal(err)
		}

		tunneler, proxyTransport, err := app.CreateNodeDialer(completedOptions)
		if err != nil {
			t.Fatal(err)
		}
		kubeAPIServerConfig, sharedInformers, versionedInformers, _, _, _, admissionPostStartHook, err := app.CreateKubeAPIServerConfig(completedOptions, tunneler, proxyTransport)
		if err != nil {
			t.Fatal(err)
		}

		kubeAPIServerConfig.ExtraConfig.APIResourceConfigSource = &allResourceSource{} // force enable all resources

		kubeAPIServer, err := app.CreateKubeAPIServer(kubeAPIServerConfig, genericapiserver.NewEmptyDelegate(), sharedInformers, versionedInformers, admissionPostStartHook)
		if err != nil {
			t.Fatal(err)
		}

		kubeClientConfigValue.Store(kubeAPIServerConfig.GenericConfig.LoopbackClientConfig)
		storageConfigValue.Store(kubeAPIServerOptions.Etcd.StorageConfig)

		if err := kubeAPIServer.GenericAPIServer.PrepareRun().Run(wait.NeverStop); err != nil {
			t.Fatal(err)
		}
	}()

	if err := wait.PollImmediate(time.Second, time.Minute, func() (done bool, err error) {
		obj := kubeClientConfigValue.Load()
		if obj == nil {
			return false, nil
		}
		kubeClientConfig := kubeClientConfigValue.Load().(*restclient.Config)
		// make a copy so we can mutate it to set GroupVersion and NegotiatedSerializer
		cfg := *kubeClientConfig
		cfg.ContentConfig.GroupVersion = &schema.GroupVersion{}
		cfg.ContentConfig.NegotiatedSerializer = legacyscheme.Codecs
		privilegedClient, err := restclient.RESTClientFor(&cfg)
		if err != nil {
			// this happens because we race the API server start
			t.Log(err)
			return false, nil
		}
		// wait for the server to be healthy
		result := privilegedClient.Get().AbsPath("/healthz").Do()
		if errResult := result.Error(); errResult != nil {
			t.Log(errResult)
			return false, nil
		}
		var status int
		result.StatusCode(&status)
		return status == http.StatusOK, nil
	}); err != nil {
		t.Fatal(err)
	}

	kubeClientConfig := kubeClientConfigValue.Load().(*restclient.Config)
	storageConfig := storageConfigValue.Load().(storagebackend.Config)

	kubeClient := clientset.NewForConfigOrDie(kubeClientConfig)
	if _, err := kubeClient.CoreV1().Namespaces().Create(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}); err != nil {
		t.Fatal(err)
	}

	client, err := newClient(*kubeClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	kvClient, err := integration.GetEtcdKVClient(storageConfig)
	if err != nil {
		t.Fatal(err)
	}

	discoveryClient := cacheddiscovery.NewMemCacheClient(kubeClient.Discovery())
	restMapper := restmapper.NewDeferredDiscoveryRESTMapper(discoveryClient)
	restMapper.Reset()

	return client, kvClient, restMapper
}

func dumpEtcdKVOnFailure(t *testing.T, kvClient clientv3.KV) {
	if t.Failed() {
		response, err := kvClient.Get(context.Background(), "/", clientv3.WithPrefix())
		if err != nil {
			t.Fatal(err)
		}

		for _, kv := range response.Kvs {
			t.Error(string(kv.Key), "->", string(kv.Value))
		}
	}
}

func addGVKToEtcdBucket(cohabitatingResources map[string]map[schema.GroupVersionKind]empty, gvk schema.GroupVersionKind, bucket string) {
	if cohabitatingResources[bucket] == nil {
		cohabitatingResources[bucket] = map[schema.GroupVersionKind]empty{}
	}
	cohabitatingResources[bucket][gvk] = empty{}
}

// getEtcdBucket assumes the last segment of the given etcd path is the name of the object.
// Thus it strips that segment to extract the object's storage "bucket" in etcd. We expect
// all objects that share the a bucket (cohabitating resources) to be stored as the same GVK.
func getEtcdBucket(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx == -1 {
		panic("path with no slashes " + path)
	}
	bucket := path[:idx]
	if len(bucket) == 0 {
		panic("invalid bucket for path " + path)
	}
	return bucket
}

// stable fields to compare as a sanity check
type metaObject struct {
	// all of type meta
	Kind       string `json:"kind,omitempty" protobuf:"bytes,1,opt,name=kind"`
	APIVersion string `json:"apiVersion,omitempty" protobuf:"bytes,2,opt,name=apiVersion"`

	// parts of object meta
	Metadata struct {
		Name      string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
		Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
	} `json:"metadata,omitempty" protobuf:"bytes,3,opt,name=metadata"`
}

func (obj *metaObject) getGVK() schema.GroupVersionKind {
	return schema.FromAPIVersionAndKind(obj.APIVersion, obj.Kind)
}

func (obj *metaObject) isEmpty() bool {
	return obj == nil || *obj == metaObject{} // compare to zero value since all fields are strings
}

type empty struct{}

type cleanupData struct {
	obj     runtime.Object
	mapping *meta.RESTMapping
}

func gvk(g, v, k string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: g, Version: v, Kind: k}
}

func createEphemeralWhiteList(gvks ...schema.GroupVersionKind) map[schema.GroupVersionKind]empty {
	ephemeral := map[schema.GroupVersionKind]empty{}
	for _, gvKind := range gvks {
		if _, ok := ephemeral[gvKind]; ok {
			panic("invalid ephemeral whitelist contains duplicate keys")
		}
		ephemeral[gvKind] = empty{}
	}
	return ephemeral
}

func jsonToMetaObject(stub []byte) (*metaObject, error) {
	obj := &metaObject{}
	if err := json.Unmarshal(stub, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func keyStringer(i interface{}) string {
	base := "\n\t"
	switch key := i.(type) {
	case string:
		return base + key
	case schema.GroupVersionResource:
		return base + key.String()
	case schema.GroupVersionKind:
		return base + key.String()
	default:
		panic("unexpected type")
	}
}

type allClient struct {
	client  *http.Client
	config  *restclient.Config
	backoff restclient.BackoffManager
}

func (c *allClient) verb(verb string, gvk schema.GroupVersionKind) (*restclient.Request, error) {
	apiPath := "/apis"
	if gvk.Group == kapi.GroupName {
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
	return restclient.NewRequest(c.client, verb, baseURL, versionedAPIPath, contentConfig, *serializers, c.backoff, c.config.RateLimiter, 0), nil
}

func (c *allClient) create(stub, ns string, mapping *meta.RESTMapping, all *[]cleanupData) error {
	req, err := c.verb("POST", mapping.GroupVersionKind)
	if err != nil {
		return err
	}
	namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	output, err := req.NamespaceIfScoped(ns, namespaced).Resource(mapping.Resource.Resource).Body(strings.NewReader(stub)).Do().Get()
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
	name, err := meta.NewAccessor().Name(obj)
	if err != nil {
		return err
	}
	ns, err := meta.NewAccessor().Namespace(obj)
	if err != nil {
		return err
	}
	return req.NamespaceIfScoped(ns, namespaced).Resource(mapping.Resource.Resource).Name(name).Do().Error()
}

func (c *allClient) cleanup(all *[]cleanupData) error {
	for i := len(*all) - 1; i >= 0; i-- { // delete in reverse order in case creation order mattered
		obj := (*all)[i].obj
		mapping := (*all)[i].mapping

		if err := c.destroy(obj, mapping); err != nil {
			return err
		}
	}
	return nil
}

func (c *allClient) createPrerequisites(mapper meta.RESTMapper, ns string, prerequisites []Prerequisite, all *[]cleanupData) error {
	for _, prerequisite := range prerequisites {
		gvk, err := mapper.KindFor(prerequisite.GvrData)
		if err != nil {
			return err
		}
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		if err := c.create(prerequisite.Stub, ns, mapping, all); err != nil {
			return err
		}
	}
	return nil
}

func newClient(config restclient.Config) (*allClient, error) {
	config.ContentConfig.NegotiatedSerializer = legacyscheme.Codecs
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

	internalGV := schema.GroupVersions{
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

func getFromEtcd(keys clientv3.KV, path string) (*metaObject, error) {
	response, err := keys.Get(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if response.More || response.Count != 1 || len(response.Kvs) != 1 {
		return nil, fmt.Errorf("Invalid etcd response (not found == %v): %#v", response.Count == 0, response)
	}
	return jsonToMetaObject(response.Kvs[0].Value)
}

func diffMaps(a, b interface{}) ([]string, []string) {
	inA := diffMapKeys(a, b, keyStringer)
	inB := diffMapKeys(b, a, keyStringer)
	return inA, inB
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

type allResourceSource struct{}

func (*allResourceSource) AnyVersionForGroupEnabled(group string) bool     { return true }
func (*allResourceSource) VersionEnabled(version schema.GroupVersion) bool { return true }
