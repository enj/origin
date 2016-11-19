package helpers

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/validation/field"
)

var ReadDeleteStrategy = readDeleteStrategy{kapi.Scheme}

type readDeleteStrategy struct{ runtime.ObjectTyper }

func (readDeleteStrategy) PrepareForCreate(ctx kapi.Context, obj runtime.Object) {}
func (readDeleteStrategy) Canonicalize(obj runtime.Object)                       {}
func (readDeleteStrategy) NamespaceScoped() bool                                 { return false }
func (readDeleteStrategy) GenerateName(base string) string                       { return base }
func (readDeleteStrategy) Validate(ctx kapi.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{field.Invalid(field.NewPath(""), obj, "object is immutable")}
}
