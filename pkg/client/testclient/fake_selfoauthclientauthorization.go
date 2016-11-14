package testclient

import (
	kapi "k8s.io/kubernetes/pkg/api"
	ktestclient "k8s.io/kubernetes/pkg/client/unversioned/testclient"
	"k8s.io/kubernetes/pkg/watch"

	oauthapi "github.com/openshift/origin/pkg/oauth/api"
)

type FakeSelfOAuthClientAuthorization struct {
	Fake *Fake
}

func (c *FakeSelfOAuthClientAuthorization) Get(name string) (*oauthapi.SelfOAuthClientAuthorization, error) {
	obj, err := c.Fake.Invokes(ktestclient.NewRootGetAction("selfOAuthClientAuthorizations", name), &oauthapi.SelfOAuthClientAuthorization{})
	if obj == nil {
		return nil, err
	}

	return obj.(*oauthapi.SelfOAuthClientAuthorization), err
}

func (c *FakeSelfOAuthClientAuthorization) List(opts kapi.ListOptions) (*oauthapi.SelfOAuthClientAuthorizationList, error) {
	obj, err := c.Fake.Invokes(ktestclient.NewRootListAction("selfOAuthClientAuthorizations", opts), &oauthapi.SelfOAuthClientAuthorizationList{})
	if obj == nil {
		return nil, err
	}

	return obj.(*oauthapi.SelfOAuthClientAuthorizationList), err
}

func (c *FakeSelfOAuthClientAuthorization) Create(inObj *oauthapi.SelfOAuthClientAuthorization) (*oauthapi.SelfOAuthClientAuthorization, error) {
	obj, err := c.Fake.Invokes(ktestclient.NewRootCreateAction("selfOAuthClientAuthorizations", inObj), inObj)
	if obj == nil {
		return nil, err
	}

	return obj.(*oauthapi.SelfOAuthClientAuthorization), err
}

func (c *FakeSelfOAuthClientAuthorization) Update(inObj *oauthapi.SelfOAuthClientAuthorization) (*oauthapi.SelfOAuthClientAuthorization, error) {
	obj, err := c.Fake.Invokes(ktestclient.NewRootUpdateAction("selfOAuthClientAuthorizations", inObj), inObj)
	if obj == nil {
		return nil, err
	}

	return obj.(*oauthapi.SelfOAuthClientAuthorization), err
}

func (c *FakeSelfOAuthClientAuthorization) Delete(name string) error {
	_, err := c.Fake.Invokes(ktestclient.NewRootDeleteAction("selfOAuthClientAuthorizations", name), &oauthapi.SelfOAuthClientAuthorization{})
	return err
}

func (c *FakeSelfOAuthClientAuthorization) Watch(opts kapi.ListOptions) (watch.Interface, error) {
	return c.Fake.InvokesWatch(ktestclient.NewRootWatchAction("selfOAuthClientAuthorizations", opts))
}
