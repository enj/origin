package oauthaccesstoken

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	kapi "k8s.io/kubernetes/pkg/api"

	scopeauthorizer "github.com/openshift/origin/pkg/authorization/authorizer/scope"
	oauthapi "github.com/openshift/origin/pkg/oauth/apis/oauth"
	"github.com/openshift/origin/pkg/oauth/apis/oauth/validation"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
)

// strategy implements behavior for OAuthAccessTokens
type strategy struct {
	runtime.ObjectTyper

	clientGetter oauthclient.Getter
}

var _ rest.RESTCreateStrategy = strategy{}
var _ rest.RESTUpdateStrategy = strategy{}

func NewStrategy(clientGetter oauthclient.Getter) strategy {
	return strategy{ObjectTyper: kapi.Scheme, clientGetter: clientGetter}
}

func (strategy) DefaultGarbageCollectionPolicy() rest.GarbageCollectionPolicy {
	return rest.Unsupported
}

func (strategy) PrepareForUpdate(ctx apirequest.Context, obj, old runtime.Object) {}

// NamespaceScoped is false for OAuth objects
func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) GenerateName(base string) string {
	return base
}

func (strategy) PrepareForCreate(ctx apirequest.Context, obj runtime.Object) {
}

// Validate validates a new token
func (s strategy) Validate(ctx apirequest.Context, obj runtime.Object) field.ErrorList {
	token := obj.(*oauthapi.OAuthAccessToken)
	validationErrors := validation.ValidateAccessToken(token)

	client, err := s.clientGetter.Get(token.ClientName, metav1.GetOptions{})
	if err != nil {
		return append(validationErrors, field.InternalError(field.NewPath("clientName"), err))
	}
	if err := scopeauthorizer.ValidateScopeRestrictions(client, token.Scopes...); err != nil {
		validationErrors = append(validationErrors, field.InternalError(field.NewPath("clientName"), err))
	}
	if timeout := client.AccessTokenTimeoutSeconds; timeout != nil {
		if *timeout != token.TimeoutsIn {
			validationErrors = append(validationErrors, field.Invalid(field.NewPath("timeoutsIn"), token.TimeoutsIn, fmt.Sprintf("must equal %d", *timeout)))
		}
	} // TODO technically we should have an else if with the default timeout from master config

	return validationErrors
}

// ValidateUpdate validates an update
func (s strategy) ValidateUpdate(ctx apirequest.Context, obj, old runtime.Object) field.ErrorList {
	oldToken := old.(*oauthapi.OAuthAccessToken)
	newToken := obj.(*oauthapi.OAuthAccessToken)
	return validation.ValidateAccessTokenUpdate(newToken, oldToken)
}

// AllowCreateOnUpdate is false for OAuth objects
func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (strategy) AllowUnconditionalUpdate() bool {
	return false
}

// Canonicalize normalizes the object after validation.
func (strategy) Canonicalize(obj runtime.Object) {
}
