package accessrestriction

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/apis/authorization/validation"
)

type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

var _ rest.GarbageCollectionDeleteStrategy = strategy{}

func (strategy) DefaultGarbageCollectionPolicy(ctx apirequest.Context) rest.GarbageCollectionPolicy {
	return rest.Unsupported
}

func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (strategy) AllowUnconditionalUpdate() bool {
	return false
}

func (strategy) PrepareForCreate(ctx apirequest.Context, obj runtime.Object) {
	_ = obj.(*authorizationapi.AccessRestriction)
}

func (strategy) PrepareForUpdate(ctx apirequest.Context, obj, old runtime.Object) {
	_ = obj.(*authorizationapi.AccessRestriction)
	_ = old.(*authorizationapi.AccessRestriction)
}

func (strategy) Canonicalize(obj runtime.Object) {}

func (strategy) Validate(ctx apirequest.Context, obj runtime.Object) field.ErrorList {
	return validation.ValidateAccessRestriction(obj.(*authorizationapi.AccessRestriction))
}

func (strategy) ValidateUpdate(ctx apirequest.Context, obj, old runtime.Object) field.ErrorList {
	return validation.ValidateAccessRestrictionUpdate(obj.(*authorizationapi.AccessRestriction), old.(*authorizationapi.AccessRestriction))
}
