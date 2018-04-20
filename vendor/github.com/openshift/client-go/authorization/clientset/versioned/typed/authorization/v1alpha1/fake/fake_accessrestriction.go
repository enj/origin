// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/openshift/api/authorization/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeAccessRestrictions implements AccessRestrictionInterface
type FakeAccessRestrictions struct {
	Fake *FakeAuthorizationV1alpha1
}

var accessrestrictionsResource = schema.GroupVersionResource{Group: "authorization.openshift.io", Version: "v1alpha1", Resource: "accessrestrictions"}

var accessrestrictionsKind = schema.GroupVersionKind{Group: "authorization.openshift.io", Version: "v1alpha1", Kind: "AccessRestriction"}

// Get takes name of the accessRestriction, and returns the corresponding accessRestriction object, and an error if there is any.
func (c *FakeAccessRestrictions) Get(name string, options v1.GetOptions) (result *v1alpha1.AccessRestriction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(accessrestrictionsResource, name), &v1alpha1.AccessRestriction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.AccessRestriction), err
}

// List takes label and field selectors, and returns the list of AccessRestrictions that match those selectors.
func (c *FakeAccessRestrictions) List(opts v1.ListOptions) (result *v1alpha1.AccessRestrictionList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(accessrestrictionsResource, accessrestrictionsKind, opts), &v1alpha1.AccessRestrictionList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.AccessRestrictionList{}
	for _, item := range obj.(*v1alpha1.AccessRestrictionList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested accessRestrictions.
func (c *FakeAccessRestrictions) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(accessrestrictionsResource, opts))
}

// Create takes the representation of a accessRestriction and creates it.  Returns the server's representation of the accessRestriction, and an error, if there is any.
func (c *FakeAccessRestrictions) Create(accessRestriction *v1alpha1.AccessRestriction) (result *v1alpha1.AccessRestriction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(accessrestrictionsResource, accessRestriction), &v1alpha1.AccessRestriction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.AccessRestriction), err
}

// Update takes the representation of a accessRestriction and updates it. Returns the server's representation of the accessRestriction, and an error, if there is any.
func (c *FakeAccessRestrictions) Update(accessRestriction *v1alpha1.AccessRestriction) (result *v1alpha1.AccessRestriction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(accessrestrictionsResource, accessRestriction), &v1alpha1.AccessRestriction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.AccessRestriction), err
}

// Delete takes name of the accessRestriction and deletes it. Returns an error if one occurs.
func (c *FakeAccessRestrictions) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(accessrestrictionsResource, name), &v1alpha1.AccessRestriction{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeAccessRestrictions) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(accessrestrictionsResource, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.AccessRestrictionList{})
	return err
}

// Patch applies the patch and returns the patched accessRestriction.
func (c *FakeAccessRestrictions) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.AccessRestriction, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(accessrestrictionsResource, name, data, subresources...), &v1alpha1.AccessRestriction{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.AccessRestriction), err
}
