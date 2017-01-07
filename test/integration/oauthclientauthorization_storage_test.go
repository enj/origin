package integration

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/client/restclient"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/serviceaccount"
	"k8s.io/kubernetes/pkg/storage"
	"k8s.io/kubernetes/pkg/storage/storagebackend/factory"
	"k8s.io/kubernetes/pkg/util/wait"

	"github.com/openshift/origin/pkg/authorization/authorizer/scope"
	osclient "github.com/openshift/origin/pkg/client"
	originrest "github.com/openshift/origin/pkg/cmd/server/origin/rest"
	oauthapi "github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/registry/helpers"
	clientauthetcd "github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization/etcd"
	saoauth "github.com/openshift/origin/pkg/serviceaccounts/oauthclient"
	userapi "github.com/openshift/origin/pkg/user/api"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"
)

type clientAuthorizationTester struct {
	asClusterAdmin osclient.OAuthClientAuthorizationInterface

	destroyFunc factory.DestroyFunc
	rawStorage  storage.Interface
	rawPrefix   string
	ns          string
	sa          kclient.ServiceAccountsInterface
	sc          kclient.SecretsInterface
	rc          *restclient.Config
	t           *testing.T
}

func (o *clientAuthorizationTester) createClientAuthorizations(clients ...*oauthapi.OAuthClientAuthorization) {
	for _, client := range clients {
		if _, err := o.asClusterAdmin.Create(client); err != nil {
			o.t.Fatalf("error creating client auth: %#v", err)
		}
	}
}

func (o *clientAuthorizationTester) oldLocationEtcdCreate(clients ...*oauthapi.OAuthClientAuthorization) {
	ctx := kapi.NewContext()
	for _, client := range clients {
		// old name format
		client.Name = client.UserName + ":" + client.ClientName
		key, err := registry.NoNamespaceKeyFunc(ctx, o.rawPrefix, client.Name)
		if err != nil {
			o.t.Fatalf("unexpected key error: %#v", err)
		}
		if err = o.rawStorage.Create(ctx, key, client, nil, 0); err != nil {
			o.t.Fatalf("unexpected create error: %#v", err)
		}
	}
}

func (o *clientAuthorizationTester) createSA(name string) *kapi.ServiceAccount {
	serviceAccount := &kapi.ServiceAccount{
		ObjectMeta: kapi.ObjectMeta{
			Name:        name,
			Namespace:   o.ns,
			Annotations: map[string]string{saoauth.OAuthRedirectModelAnnotationURIPrefix + "foo": "http://bar"}},
	}
	serviceAccount, err := o.sa.Create(serviceAccount)
	if err != nil {
		o.t.Fatalf("error creating SA: %#v", err)
	}
	secret := &kapi.Secret{
		ObjectMeta: kapi.ObjectMeta{
			Name:        serviceAccount.Name,
			Annotations: map[string]string{kapi.ServiceAccountNameKey: serviceAccount.Name},
		},
		Type: kapi.SecretTypeServiceAccountToken,
	}
	if _, err := o.sc.Create(secret); err != nil {
		o.t.Fatalf("error creating secret: %#v", err)
	}
	return serviceAccount
}

func (o *clientAuthorizationTester) createUser(userName string) (*userapi.User, osclient.SelfOAuthClientAuthorizationInterface) {
	userClient, _, _, err := testutil.GetClientForUser(*o.rc, userName)
	if err != nil {
		o.t.Fatalf("error getting user client for %s: %#v", userName, err)
	}
	self, err := userClient.Users().Get("~")
	if err != nil {
		o.t.Fatalf("error getting user UID for %s: %#v", userName, err)
	}
	return self, userClient.SelfOAuthClientAuthorizations()
}

func assertEqualList(testName string, expected *oauthapi.OAuthClientAuthorizationList, actual *oauthapi.OAuthClientAuthorizationList) (bool, string) {
	zeroIgnoredFields(actual)
	sort.Sort(sortList(*expected))
	sort.Sort(sortList(*actual))
	if !reflect.DeepEqual(expected, actual) {
		return false, fmt.Sprintf("%s failed\nexpected:\n%#v\ngot:\n%#v", testName, expected, actual)
	}
	return true, ""
}

func zeroIgnoredFields(list *oauthapi.OAuthClientAuthorizationList) {
	list.ResourceVersion = ""
	list.SelfLink = ""
	l := list.Items
	for i := range l {
		l[i].Name = ""
		l[i].ResourceVersion = ""
		l[i].UID = ""
		l[i].SelfLink = ""
		l[i].CreationTimestamp = unversioned.Time{}
	}
}

func assertEqualSelfList(testName string, expected *oauthapi.OAuthClientAuthorizationList, actual *oauthapi.SelfOAuthClientAuthorizationList) (bool, string) {
	zeroSelfIgnoredFields(actual)
	e := clientauthetcd.ToSelfList(expected).(*oauthapi.SelfOAuthClientAuthorizationList)
	sort.Sort(sortSelfList(*e))
	sort.Sort(sortSelfList(*actual))
	if e.Items == nil {
		e.Items = []oauthapi.SelfOAuthClientAuthorization{} // don't want this to be nil for comparision with actual
	}
	if !reflect.DeepEqual(e, actual) {
		return false, fmt.Sprintf("%s failed\nexpected:\n%#v\ngot:\n%#v", testName, e, actual)
	}
	return true, ""
}

func zeroSelfIgnoredFields(list *oauthapi.SelfOAuthClientAuthorizationList) {
	list.ResourceVersion = ""
	list.SelfLink = ""
	l := list.Items
	for i := range l {
		l[i].ResourceVersion = ""
		l[i].UID = ""
		l[i].SelfLink = ""
		l[i].CreationTimestamp = unversioned.Time{}
	}
}

func assertGetSuccess(testName string, auth osclient.SelfOAuthClientAuthorizationInterface, expected *oauthapi.OAuthClientAuthorizationList, saList ...*kapi.ServiceAccount) (bool, string) {
	actual := &oauthapi.SelfOAuthClientAuthorizationList{Items: []oauthapi.SelfOAuthClientAuthorization{}}
	for _, sa := range saList {
		data, err := auth.Get(getSAName(sa))
		if err != nil {
			return false, fmt.Sprintf("%s failed: error getting self client auth: %#v", testName, err)
		}
		actual.Items = append(actual.Items, *data)
	}
	return assertEqualSelfList(testName, expected, actual)
}

func assertGetFailure(testName string, auth osclient.SelfOAuthClientAuthorizationInterface, saList ...*kapi.ServiceAccount) (bool, string) {
	for _, sa := range saList {
		if _, err := auth.Get(getSAName(sa)); err == nil || !kubeerr.IsNotFound(err) {
			return false, fmt.Sprintf("%s failed: did NOT return NotFound error when getting self client auth: %#v", testName, err)
		}
	}
	return true, ""
}

func (o *clientAuthorizationTester) cleanUp() {
	allAuths, err := o.asClusterAdmin.List(kapi.ListOptions{})
	if err != nil {
		o.t.Fatalf("cleanup failed to list auths: %#v", err)
	}
	for _, auth := range allAuths.Items {
		if err := o.asClusterAdmin.Delete(auth.Name); err != nil {
			o.t.Fatalf("cleanup failed to delete auth %#v: %#v", auth, err)
		}
	}
}

func (o *clientAuthorizationTester) backoffAssert(assert func() (bool, string)) {
	backoff := wait.Backoff{
		Steps:    5,
		Duration: 2 * time.Second,
		Factor:   2.0,
		Jitter:   0.1,
	}
	reason := ""
	status := false
	if err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		status, reason = assert()
		return status, nil
	}); err != nil {
		o.t.Errorf("%s %#v", reason, err)
	}
}

func newOAuthClientAuthorizationHandler(t *testing.T) *clientAuthorizationTester {
	masterConfig, err := testserver.DefaultMasterOptions()
	if err != nil {
		t.Fatalf("error getting master config: %#v", err)
	}

	kubeConfigFile, err := testserver.StartConfiguredMaster(masterConfig)
	if err != nil {
		t.Fatalf("error starting server: %#v", err)
	}
	kubeClient, err := testutil.GetClusterAdminKubeClient(kubeConfigFile)
	if err != nil {
		t.Fatalf("error getting client: %#v", err)
	}
	openshiftClient, err := testutil.GetClusterAdminClient(kubeConfigFile)
	if err != nil {
		t.Fatalf("error getting openshift client: %#v", err)
	}

	clusterAdminConfig, err := testutil.GetClusterAdminClientConfig(kubeConfigFile)
	if err != nil {
		t.Fatalf("error getting openshift client config: %v", err)
	}

	optsGetter := originrest.StorageOptions(*masterConfig)
	opts, err := optsGetter.GetRESTOptions(oauthapi.Resource("oauthclientauthorizations"))
	if err != nil {
		t.Fatalf("error getting oauthclientauthorizations RESTOptions: %#v", err)
	}

	clientAuthRawStorage, clientAuthDestroyFunc := generic.NewRawStorage(opts.StorageConfig)

	ns, err := kubeClient.Namespaces().Create(&kapi.Namespace{ObjectMeta: kapi.ObjectMeta{Name: "oauthclientauthorizationtest"}})
	if err != nil {
		t.Fatalf("error creating test namespace: %#v", err)
	}

	return &clientAuthorizationTester{
		asClusterAdmin: openshiftClient.OAuthClientAuthorizations(),

		destroyFunc: clientAuthDestroyFunc,
		rawStorage:  clientAuthRawStorage,
		rawPrefix:   opts.ResourcePrefix,
		ns:          ns.Name,
		rc:          clusterAdminConfig,
		sa:          kubeClient.ServiceAccounts(ns.Name),
		sc:          kubeClient.Secrets(ns.Name),
		t:           t,
	}
}

func newOAuthClientAuthorization(sa *kapi.ServiceAccount, user *userapi.User, scopes ...string) *oauthapi.OAuthClientAuthorization {
	client := &oauthapi.OAuthClientAuthorization{
		ClientName: getSAName(sa),
		UserName:   user.GetName(),
		UserUID:    string(user.GetUID()),
		Scopes:     scopes,
	}
	return client
}

func getSAName(sa *kapi.ServiceAccount) string {
	return serviceaccount.MakeUsername(sa.Namespace, sa.Name)
}

func newOAuthClientAuthorizationList(in ...*oauthapi.OAuthClientAuthorization) *oauthapi.OAuthClientAuthorizationList {
	out := []oauthapi.OAuthClientAuthorization{}
	for _, client := range in {
		out = append(out, *client)
	}
	return &oauthapi.OAuthClientAuthorizationList{
		Items: out,
	}
}

type sortList oauthapi.OAuthClientAuthorizationList

func (s sortList) Len() int      { return len(s.Items) }
func (s sortList) Swap(i, j int) { s.Items[i], s.Items[j] = s.Items[j], s.Items[i] }
func (s sortList) Less(i, j int) bool {
	return helpers.MakeClientAuthorizationName(s.Items[i].UserName, s.Items[i].ClientName) <
		helpers.MakeClientAuthorizationName(s.Items[j].UserName, s.Items[j].ClientName)
}

type sortSelfList oauthapi.SelfOAuthClientAuthorizationList

func (s sortSelfList) Len() int           { return len(s.Items) }
func (s sortSelfList) Swap(i, j int)      { s.Items[i], s.Items[j] = s.Items[j], s.Items[i] }
func (s sortSelfList) Less(i, j int) bool { return s.Items[i].ClientName < s.Items[j].ClientName }

// TestOAuthClientAuthorizationStorage makes sure that OAuthClientAuthorizations stored at both
// the old and new locations are accessible by the cluster admin.  It also checks to make sure that
// the user can "get", "list", "watch", "delete", "deletecollection" their (new location) SelfOAuthClientAuthorizations.
func TestOAuthClientAuthorizationStorage(t *testing.T) {
	testutil.RequireEtcd(t)
	defer testutil.DumpEtcdOnFailure(t)
	clientTester := newOAuthClientAuthorizationHandler(t)
	defer clientTester.destroyFunc()

	// Reused variables
	var err error
	var expected, actual *oauthapi.OAuthClientAuthorizationList
	var actualSelf *oauthapi.SelfOAuthClientAuthorizationList
	var opts kapi.ListOptions

	// Create some SAs to use in tests
	sa1 := clientTester.createSA("sa1")
	sa2 := clientTester.createSA("sa2")
	sa3 := clientTester.createSA("sa3")
	sa4 := clientTester.createSA("sa4")
	sa5 := clientTester.createSA("sa5")

	// Create some users to use in tests
	alice, aliceAuth := clientTester.createUser("alice")
	bob, bobAuth := clientTester.createUser("bob")
	chuck, chuckAuth := clientTester.createUser("chuck")
	david, davidAuth := clientTester.createUser("david")

	// Check get and list (no UID checks)
	{
		defer clientTester.cleanUp()

		// create old data
		clientTester.oldLocationEtcdCreate(
			newOAuthClientAuthorization(sa1, alice),
			newOAuthClientAuthorization(sa1, bob),
			newOAuthClientAuthorization(sa2, chuck),
		)

		// create new data
		clientTester.createClientAuthorizations(
			newOAuthClientAuthorization(sa3, david, scope.UserInfo),
			newOAuthClientAuthorization(sa4, alice, scope.UserInfo),
			newOAuthClientAuthorization(sa5, bob, scope.UserInfo),
			newOAuthClientAuthorization(sa2, bob, scope.UserInfo),
		)

		// cluster admin should see everything, new and old
		expected = newOAuthClientAuthorizationList(
			newOAuthClientAuthorization(sa1, alice),
			newOAuthClientAuthorization(sa1, bob),
			newOAuthClientAuthorization(sa2, chuck),
			newOAuthClientAuthorization(sa3, david, scope.UserInfo),
			newOAuthClientAuthorization(sa4, alice, scope.UserInfo),
			newOAuthClientAuthorization(sa5, bob, scope.UserInfo),
			newOAuthClientAuthorization(sa2, bob, scope.UserInfo),
		)

		clientTester.backoffAssert(func() (bool, string) {
			actual, err = clientTester.asClusterAdmin.List(opts)
			if err != nil {
				t.Fatalf("error listing client auths: %#v", err)
			}
			return assertEqualList("cluster admin sees all", expected, actual)
		})

		// normal users should only see their new clients

		// alice
		expected = newOAuthClientAuthorizationList(
			newOAuthClientAuthorization(sa4, alice, scope.UserInfo),
		)
		clientTester.backoffAssert(func() (bool, string) {
			if actualSelf, err = aliceAuth.List(opts); err != nil {
				t.Fatalf("error listing self client auths: %#v", err)
			}
			return assertEqualSelfList("alice list", expected, actualSelf)
		})
		clientTester.backoffAssert(func() (bool, string) { return assertGetSuccess("alice get", aliceAuth, expected, sa4) })
		clientTester.backoffAssert(func() (bool, string) { return assertGetFailure("alice not get", aliceAuth, sa1, sa2, sa3, sa5) })

		// bob
		expected = newOAuthClientAuthorizationList(
			newOAuthClientAuthorization(sa5, bob, scope.UserInfo),
			newOAuthClientAuthorization(sa2, bob, scope.UserInfo),
		)
		clientTester.backoffAssert(func() (bool, string) {
			if actualSelf, err = bobAuth.List(opts); err != nil {
				t.Fatalf("error listing self client auths: %#v", err)
			}
			return assertEqualSelfList("bob list", expected, actualSelf)
		})
		clientTester.backoffAssert(func() (bool, string) { return assertGetSuccess("bob get", bobAuth, expected, sa2, sa5) })
		clientTester.backoffAssert(func() (bool, string) { return assertGetFailure("bob not get", bobAuth, sa1, sa3, sa4) })

		// chuck
		expected = newOAuthClientAuthorizationList(
		// should be empty
		)
		clientTester.backoffAssert(func() (bool, string) {
			if actualSelf, err = chuckAuth.List(opts); err != nil {
				t.Fatalf("error listing self client auths: %#v", err)
			}
			return assertEqualSelfList("chuck list", expected, actualSelf)
		})
		clientTester.backoffAssert(func() (bool, string) { return assertGetSuccess("chuck get", chuckAuth, expected) }) // no SAs
		clientTester.backoffAssert(func() (bool, string) { return assertGetFailure("chuck not get", chuckAuth, sa1, sa2, sa3, sa4, sa5) })

		// david
		expected = newOAuthClientAuthorizationList(
			newOAuthClientAuthorization(sa3, david, scope.UserInfo),
		)
		clientTester.backoffAssert(func() (bool, string) {
			if actualSelf, err = davidAuth.List(opts); err != nil {
				t.Fatalf("error listing self client auths: %#v", err)
			}
			return assertEqualSelfList("david list", expected, actualSelf)
		})
		clientTester.backoffAssert(func() (bool, string) { return assertGetSuccess("david get", davidAuth, expected, sa3) })
		clientTester.backoffAssert(func() (bool, string) { return assertGetFailure("david not get", davidAuth, sa1, sa2, sa4, sa5) })
	}

	// Check delete and deletecollection
	{
		// TODO
	}

	// Check watch
	{
		// TODO
	}

	// Check watch from resource version 0
	{
		// TODO
	}

	// Check get and list (with UID checks)
	{
		// TODO
	}
}
