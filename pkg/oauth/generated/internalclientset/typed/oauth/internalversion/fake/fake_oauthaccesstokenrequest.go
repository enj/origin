package fake

import (
	oauth "github.com/openshift/origin/pkg/oauth/apis/oauth"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeOAuthAccessTokenRequests implements OAuthAccessTokenRequestInterface
type FakeOAuthAccessTokenRequests struct {
	Fake *FakeOauth
}

var oauthaccesstokenrequestsResource = schema.GroupVersionResource{Group: "oauth.openshift.io", Version: "", Resource: "oauthaccesstokenrequests"}

var oauthaccesstokenrequestsKind = schema.GroupVersionKind{Group: "oauth.openshift.io", Version: "", Kind: "OAuthAccessTokenRequest"}

// Get takes name of the oAuthAccessTokenRequest, and returns the corresponding oAuthAccessTokenRequest object, and an error if there is any.
func (c *FakeOAuthAccessTokenRequests) Get(name string, options v1.GetOptions) (result *oauth.OAuthAccessTokenRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(oauthaccesstokenrequestsResource, name), &oauth.OAuthAccessTokenRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*oauth.OAuthAccessTokenRequest), err
}

// List takes label and field selectors, and returns the list of OAuthAccessTokenRequests that match those selectors.
func (c *FakeOAuthAccessTokenRequests) List(opts v1.ListOptions) (result *oauth.OAuthAccessTokenRequestList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(oauthaccesstokenrequestsResource, oauthaccesstokenrequestsKind, opts), &oauth.OAuthAccessTokenRequestList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &oauth.OAuthAccessTokenRequestList{}
	for _, item := range obj.(*oauth.OAuthAccessTokenRequestList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested oAuthAccessTokenRequests.
func (c *FakeOAuthAccessTokenRequests) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(oauthaccesstokenrequestsResource, opts))
}

// Create takes the representation of a oAuthAccessTokenRequest and creates it.  Returns the server's representation of the oAuthAccessTokenRequest, and an error, if there is any.
func (c *FakeOAuthAccessTokenRequests) Create(oAuthAccessTokenRequest *oauth.OAuthAccessTokenRequest) (result *oauth.OAuthAccessTokenRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(oauthaccesstokenrequestsResource, oAuthAccessTokenRequest), &oauth.OAuthAccessTokenRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*oauth.OAuthAccessTokenRequest), err
}

// Update takes the representation of a oAuthAccessTokenRequest and updates it. Returns the server's representation of the oAuthAccessTokenRequest, and an error, if there is any.
func (c *FakeOAuthAccessTokenRequests) Update(oAuthAccessTokenRequest *oauth.OAuthAccessTokenRequest) (result *oauth.OAuthAccessTokenRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(oauthaccesstokenrequestsResource, oAuthAccessTokenRequest), &oauth.OAuthAccessTokenRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*oauth.OAuthAccessTokenRequest), err
}

// Delete takes name of the oAuthAccessTokenRequest and deletes it. Returns an error if one occurs.
func (c *FakeOAuthAccessTokenRequests) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(oauthaccesstokenrequestsResource, name), &oauth.OAuthAccessTokenRequest{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeOAuthAccessTokenRequests) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(oauthaccesstokenrequestsResource, listOptions)

	_, err := c.Fake.Invokes(action, &oauth.OAuthAccessTokenRequestList{})
	return err
}

// Patch applies the patch and returns the patched oAuthAccessTokenRequest.
func (c *FakeOAuthAccessTokenRequests) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *oauth.OAuthAccessTokenRequest, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(oauthaccesstokenrequestsResource, name, data, subresources...), &oauth.OAuthAccessTokenRequest{})
	if obj == nil {
		return nil, err
	}
	return obj.(*oauth.OAuthAccessTokenRequest), err
}
