package oauthclientauthorization

import (
	"fmt"

	"github.com/openshift/origin/pkg/oauth/api"
	"github.com/openshift/origin/pkg/oauth/api/validation"
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/validation/field"

	scopeauthorizer "github.com/openshift/origin/pkg/authorization/authorizer/scope"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclient"
	oauthclientauthorizationhelpers "github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization/helpers"
)

// strategy implements behavior for OAuthClientAuthorization objects
type strategy struct {
	runtime.ObjectTyper

	clientGetter oauthclient.Getter
}

func NewStrategy(clientGetter oauthclient.Getter) strategy {
	return strategy{ObjectTyper: kapi.Scheme, clientGetter: clientGetter}
}

func (strategy) PrepareForUpdate(ctx kapi.Context, obj, old runtime.Object) {
	auth := oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(obj)
	auth.Name = oauthclientauthorizationhelpers.GetClientAuthorizationName(auth.UserName, auth.UserUID, auth.ClientName)
}

// NamespaceScoped is false for OAuth objects
func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) GenerateName(base string) string {
	return base
}

func (strategy) PrepareForCreate(ctx kapi.Context, obj runtime.Object) {
	auth := oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(obj)
	auth.Name = oauthclientauthorizationhelpers.GetClientAuthorizationName(auth.UserName, auth.UserUID, auth.ClientName)
}

// Canonicalize normalizes the object after validation.
func (strategy) Canonicalize(obj runtime.Object) {
}

// validateSelfOAuthClientAuthorization must be run before any calls to `ObjectToOAuthClientAuthorization` as that loses the self type information
func validateSelfOAuthClientAuthorization(ctx kapi.Context, obj runtime.Object) field.ErrorList {
	validationErrors := field.ErrorList{}
	if auth, isSelfObj := obj.(*api.SelfOAuthClientAuthorization); isSelfObj {
		if user, ok := kapi.UserFrom(ctx); !ok {
			validationErrors = append(validationErrors, field.InternalError(field.NewPath("user"), fmt.Errorf("User parameter required.")))
		} else {
			name := user.GetName()
			if name != auth.UserName {
				validationErrors = append(validationErrors, field.Invalid(field.NewPath("userName"), auth.UserName, "must equal "+name))
			}
			uid := user.GetUID()
			if uid != auth.UserUID {
				validationErrors = append(validationErrors, field.Invalid(field.NewPath("userUID"), auth.UserUID, "must equal "+uid))
			}
			if expectedName := oauthclientauthorizationhelpers.GetClientAuthorizationName(name, uid, auth.ClientName); auth.Name != expectedName {
				validationErrors = append(validationErrors, field.Invalid(field.NewPath("name"), auth.Name, "must equal "+expectedName))
			}
		}
	}
	return validationErrors
}

func (s strategy) validateClientAndScopes(ctx kapi.Context, auth *api.OAuthClientAuthorization, validationErrors field.ErrorList) {
	client, err := s.clientGetter.GetClient(ctx, auth.ClientName)
	if err != nil {
		validationErrors = append(validationErrors, field.InternalError(field.NewPath("clientName"), err))
		return
	}
	if err := scopeauthorizer.ValidateScopeRestrictions(client, auth.Scopes...); err != nil {
		validationErrors = append(validationErrors, field.InternalError(field.NewPath("clientName"), err))
	}
}

// Validate validates a new client
func (s strategy) Validate(ctx kapi.Context, obj runtime.Object) field.ErrorList {
	validationErrors := validateSelfOAuthClientAuthorization(ctx, obj)
	auth := oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(obj)
	validationErrors = append(validationErrors, validation.ValidateClientAuthorization(auth)...)
	s.validateClientAndScopes(ctx, auth, validationErrors)
	return validationErrors
}

// ValidateUpdate validates a client auth update
func (s strategy) ValidateUpdate(ctx kapi.Context, obj runtime.Object, old runtime.Object) field.ErrorList {
	validationErrors := validateSelfOAuthClientAuthorization(ctx, obj)
	clientAuth := oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(obj)
	oldClientAuth := oauthclientauthorizationhelpers.ObjectToOAuthClientAuthorization(old)
	validationErrors = append(validationErrors, validation.ValidateClientAuthorizationUpdate(clientAuth, oldClientAuth)...)
	s.validateClientAndScopes(ctx, clientAuth, validationErrors)
	return validationErrors
}

func (strategy) AllowCreateOnUpdate() bool {
	return true
}

func (strategy) AllowUnconditionalUpdate() bool {
	return false
}

// Matcher returns a generic matcher for a given label and field selector.
func Matcher(label labels.Selector, field fields.Selector) *generic.SelectionPredicate {
	return &generic.SelectionPredicate{
		Label: label,
		Field: field,
		GetAttrs: func(o runtime.Object) (labels.Set, fields.Set, error) {
			obj, ok := oauthclientauthorizationhelpers.SafeObjectToOAuthClientAuthorization(o)
			if !ok {
				return nil, nil, fmt.Errorf("not an OAuthClientAuthorization")
			}
			return labels.Set(obj.Labels), SelectableFields(obj), nil
		},
	}
}

// SelectableFields returns a field set that can be used for filter selection
func SelectableFields(obj *api.OAuthClientAuthorization) fields.Set {
	return api.OAuthClientAuthorizationToSelectableFields(obj)
}
