package internalversion

import (
	oauth "github.com/openshift/origin/pkg/oauth/apis/oauth"
	scheme "github.com/openshift/origin/pkg/oauth/generated/internalclientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// OAuthAccessTokenRequestsGetter has a method to return a OAuthAccessTokenRequestInterface.
// A group's client should implement this interface.
type OAuthAccessTokenRequestsGetter interface {
	OAuthAccessTokenRequests() OAuthAccessTokenRequestInterface
}

// OAuthAccessTokenRequestInterface has methods to work with OAuthAccessTokenRequest resources.
type OAuthAccessTokenRequestInterface interface {
	Create(*oauth.OAuthAccessTokenRequest) (*oauth.OAuthAccessTokenRequest, error)
	Update(*oauth.OAuthAccessTokenRequest) (*oauth.OAuthAccessTokenRequest, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*oauth.OAuthAccessTokenRequest, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *oauth.OAuthAccessTokenRequest, err error)
	OAuthAccessTokenRequestExpansion
}

// oAuthAccessTokenRequests implements OAuthAccessTokenRequestInterface
type oAuthAccessTokenRequests struct {
	client rest.Interface
}

// newOAuthAccessTokenRequests returns a OAuthAccessTokenRequests
func newOAuthAccessTokenRequests(c *OauthClient) *oAuthAccessTokenRequests {
	return &oAuthAccessTokenRequests{
		client: c.RESTClient(),
	}
}

// Get takes name of the oAuthAccessTokenRequest, and returns the corresponding oAuthAccessTokenRequest object, and an error if there is any.
func (c *oAuthAccessTokenRequests) Get(name string, options v1.GetOptions) (result *oauth.OAuthAccessTokenRequest, err error) {
	result = &oauth.OAuthAccessTokenRequest{}
	err = c.client.Get().
		Resource("oauthaccesstokenrequests").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested oAuthAccessTokenRequests.
func (c *oAuthAccessTokenRequests) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Resource("oauthaccesstokenrequests").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a oAuthAccessTokenRequest and creates it.  Returns the server's representation of the oAuthAccessTokenRequest, and an error, if there is any.
func (c *oAuthAccessTokenRequests) Create(oAuthAccessTokenRequest *oauth.OAuthAccessTokenRequest) (result *oauth.OAuthAccessTokenRequest, err error) {
	result = &oauth.OAuthAccessTokenRequest{}
	err = c.client.Post().
		Resource("oauthaccesstokenrequests").
		Body(oAuthAccessTokenRequest).
		Do().
		Into(result)
	return
}

// Update takes the representation of a oAuthAccessTokenRequest and updates it. Returns the server's representation of the oAuthAccessTokenRequest, and an error, if there is any.
func (c *oAuthAccessTokenRequests) Update(oAuthAccessTokenRequest *oauth.OAuthAccessTokenRequest) (result *oauth.OAuthAccessTokenRequest, err error) {
	result = &oauth.OAuthAccessTokenRequest{}
	err = c.client.Put().
		Resource("oauthaccesstokenrequests").
		Name(oAuthAccessTokenRequest.Name).
		Body(oAuthAccessTokenRequest).
		Do().
		Into(result)
	return
}

// Delete takes name of the oAuthAccessTokenRequest and deletes it. Returns an error if one occurs.
func (c *oAuthAccessTokenRequests) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("oauthaccesstokenrequests").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *oAuthAccessTokenRequests) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Resource("oauthaccesstokenrequests").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched oAuthAccessTokenRequest.
func (c *oAuthAccessTokenRequests) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *oauth.OAuthAccessTokenRequest, err error) {
	result = &oauth.OAuthAccessTokenRequest{}
	err = c.client.Patch(pt).
		Resource("oauthaccesstokenrequests").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
