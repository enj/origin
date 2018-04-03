package internalversion

import (
	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	scheme "github.com/openshift/origin/pkg/authorization/generated/internalclientset/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// AccessRestrictionsGetter has a method to return a AccessRestrictionInterface.
// A group's client should implement this interface.
type AccessRestrictionsGetter interface {
	AccessRestrictions() AccessRestrictionInterface
}

// AccessRestrictionInterface has methods to work with AccessRestriction resources.
type AccessRestrictionInterface interface {
	Create(*authorization.AccessRestriction) (*authorization.AccessRestriction, error)
	Update(*authorization.AccessRestriction) (*authorization.AccessRestriction, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*authorization.AccessRestriction, error)
	List(opts v1.ListOptions) (*authorization.AccessRestrictionList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *authorization.AccessRestriction, err error)
	AccessRestrictionExpansion
}

// accessRestrictions implements AccessRestrictionInterface
type accessRestrictions struct {
	client rest.Interface
}

// newAccessRestrictions returns a AccessRestrictions
func newAccessRestrictions(c *AuthorizationClient) *accessRestrictions {
	return &accessRestrictions{
		client: c.RESTClient(),
	}
}

// Get takes name of the accessRestriction, and returns the corresponding accessRestriction object, and an error if there is any.
func (c *accessRestrictions) Get(name string, options v1.GetOptions) (result *authorization.AccessRestriction, err error) {
	result = &authorization.AccessRestriction{}
	err = c.client.Get().
		Resource("accessrestrictions").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of AccessRestrictions that match those selectors.
func (c *accessRestrictions) List(opts v1.ListOptions) (result *authorization.AccessRestrictionList, err error) {
	result = &authorization.AccessRestrictionList{}
	err = c.client.Get().
		Resource("accessrestrictions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested accessRestrictions.
func (c *accessRestrictions) Watch(opts v1.ListOptions) (watch.Interface, error) {
	opts.Watch = true
	return c.client.Get().
		Resource("accessrestrictions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch()
}

// Create takes the representation of a accessRestriction and creates it.  Returns the server's representation of the accessRestriction, and an error, if there is any.
func (c *accessRestrictions) Create(accessRestriction *authorization.AccessRestriction) (result *authorization.AccessRestriction, err error) {
	result = &authorization.AccessRestriction{}
	err = c.client.Post().
		Resource("accessrestrictions").
		Body(accessRestriction).
		Do().
		Into(result)
	return
}

// Update takes the representation of a accessRestriction and updates it. Returns the server's representation of the accessRestriction, and an error, if there is any.
func (c *accessRestrictions) Update(accessRestriction *authorization.AccessRestriction) (result *authorization.AccessRestriction, err error) {
	result = &authorization.AccessRestriction{}
	err = c.client.Put().
		Resource("accessrestrictions").
		Name(accessRestriction.Name).
		Body(accessRestriction).
		Do().
		Into(result)
	return
}

// Delete takes name of the accessRestriction and deletes it. Returns an error if one occurs.
func (c *accessRestrictions) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("accessrestrictions").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *accessRestrictions) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	return c.client.Delete().
		Resource("accessrestrictions").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched accessRestriction.
func (c *accessRestrictions) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *authorization.AccessRestriction, err error) {
	result = &authorization.AccessRestriction{}
	err = c.client.Patch(pt).
		Resource("accessrestrictions").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
