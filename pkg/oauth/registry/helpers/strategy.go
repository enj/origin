package helpers

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/validation/field"
)

var ReadDeleteStrategy = readDeleteStrategy{kapi.Scheme}

type readDeleteStrategy struct{ runtime.ObjectTyper }

func (readDeleteStrategy) PrepareForUpdate(ctx kapi.Context, obj, old runtime.Object) {}
func (readDeleteStrategy) PrepareForCreate(ctx kapi.Context, obj runtime.Object)      {}
func (readDeleteStrategy) Canonicalize(obj runtime.Object)                            {}

func (readDeleteStrategy) NamespaceScoped() bool {
	return false
}

func (readDeleteStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (readDeleteStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (readDeleteStrategy) GenerateName(base string) string {
	return base
}

func (readDeleteStrategy) Validate(ctx kapi.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{field.Invalid(field.NewPath(""), obj, "object is immutable")}
}

func (s readDeleteStrategy) ValidateUpdate(ctx kapi.Context, obj runtime.Object, old runtime.Object) field.ErrorList {
	return s.Validate(ctx, obj)
}
