package client

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/watch"

	oauthapi "github.com/openshift/origin/pkg/oauth/api"
)

type SelfOAuthClientAuthorizationsInterface interface {
	SelfOAuthClientAuthorizations() SelfOAuthClientAuthorizationInterface
}

type SelfOAuthClientAuthorizationInterface interface {
	Create(obj *oauthapi.OAuthClientAuthorization) (*oauthapi.OAuthClientAuthorization, error)
	List(opts kapi.ListOptions) (*oauthapi.OAuthClientAuthorizationList, error)
	Get(name string) (*oauthapi.OAuthClientAuthorization, error)
	Update(obj *oauthapi.OAuthClientAuthorization) (*oauthapi.OAuthClientAuthorization, error)
	Delete(name string) error
	Watch(opts kapi.ListOptions) (watch.Interface, error)
}

type selfOAuthClientAuthorizations struct {
	r *Client
}

func newSelfOAuthClientAuthorizations(c *Client) *selfOAuthClientAuthorizations {
	return &selfOAuthClientAuthorizations{
		r: c,
	}
}

func (c *selfOAuthClientAuthorizations) Create(obj *oauthapi.OAuthClientAuthorization) (result *oauthapi.OAuthClientAuthorization, err error) {
	result = &oauthapi.OAuthClientAuthorization{}
	err = c.r.Post().Resource("selfOAuthClientAuthorizations").Body(obj).Do().Into(result)
	return
}

func (c *selfOAuthClientAuthorizations) Update(obj *oauthapi.OAuthClientAuthorization) (result *oauthapi.OAuthClientAuthorization, err error) {
	result = &oauthapi.OAuthClientAuthorization{}
	err = c.r.Put().Resource("selfOAuthClientAuthorizations").Name(obj.Name).Body(obj).Do().Into(result)
	return
}

func (c *selfOAuthClientAuthorizations) List(opts kapi.ListOptions) (result *oauthapi.OAuthClientAuthorizationList, err error) {
	result = &oauthapi.OAuthClientAuthorizationList{}
	err = c.r.Get().Resource("selfOAuthClientAuthorizations").VersionedParams(&opts, kapi.ParameterCodec).Do().Into(result)
	return
}

func (c *selfOAuthClientAuthorizations) Get(name string) (result *oauthapi.OAuthClientAuthorization, err error) {
	result = &oauthapi.OAuthClientAuthorization{}
	err = c.r.Get().Resource("selfOAuthClientAuthorizations").Name(name).Do().Into(result)
	return
}

func (c *selfOAuthClientAuthorizations) Delete(name string) (err error) {
	err = c.r.Delete().Resource("selfOAuthClientAuthorizations").Name(name).Do().Error()
	return
}

func (c *selfOAuthClientAuthorizations) Watch(opts kapi.ListOptions) (watch.Interface, error) {
	return c.r.Get().Prefix("watch").Resource("selfOAuthClientAuthorizations").VersionedParams(&opts, kapi.ParameterCodec).Watch()
}
