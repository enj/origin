package identitymetadata

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	userapi "github.com/openshift/origin/pkg/user/apis/user"
)

type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

var Strategy = strategy{ObjectTyper: legacyscheme.Scheme, NameGenerator: names.SimpleNameGenerator}

var _ rest.GarbageCollectionDeleteStrategy = strategy{}

func (strategy) DefaultGarbageCollectionPolicy(_ context.Context) rest.GarbageCollectionPolicy {
	return rest.Unsupported
}

func (strategy) NamespaceScoped() bool {
	return false
}

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	_ = obj.(*userapi.IdentityMetadata)
}

func (strategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	_ = obj.(*userapi.IdentityMetadata)
}

func (strategy) Canonicalize(obj runtime.Object) {
	_ = obj.(*userapi.IdentityMetadata)
}

func (strategy) AllowCreateOnUpdate() bool {
	return false
}

func (strategy) AllowUnconditionalUpdate() bool {
	return false
}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return nil // TODO
}

func (strategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return nil // TODO
}
