// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/openshift/api/authorization/v1alpha1"
	"github.com/openshift/client-go/authorization/clientset/versioned/scheme"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer"
	rest "k8s.io/client-go/rest"
)

type AuthorizationV1alpha1Interface interface {
	RESTClient() rest.Interface
	AccessRestrictionsGetter
}

// AuthorizationV1alpha1Client is used to interact with features provided by the authorization.openshift.io group.
type AuthorizationV1alpha1Client struct {
	restClient rest.Interface
}

func (c *AuthorizationV1alpha1Client) AccessRestrictions() AccessRestrictionInterface {
	return newAccessRestrictions(c)
}

// NewForConfig creates a new AuthorizationV1alpha1Client for the given config.
func NewForConfig(c *rest.Config) (*AuthorizationV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &AuthorizationV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new AuthorizationV1alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *AuthorizationV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new AuthorizationV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *AuthorizationV1alpha1Client {
	return &AuthorizationV1alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v1alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = serializer.DirectCodecFactory{CodecFactory: scheme.Codecs}

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *AuthorizationV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
