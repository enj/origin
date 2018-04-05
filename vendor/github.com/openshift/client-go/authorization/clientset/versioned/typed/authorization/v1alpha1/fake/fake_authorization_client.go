package fake

import (
	v1alpha1 "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeAuthorizationV1alpha1 struct {
	*testing.Fake
}

func (c *FakeAuthorizationV1alpha1) AccessRestrictions() v1alpha1.AccessRestrictionInterface {
	return &FakeAccessRestrictions{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeAuthorizationV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
