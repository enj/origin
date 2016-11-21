package helpers

import "k8s.io/kubernetes/pkg/api/rest"

var CannotCreateStrategy = (*rest.RESTCreateStrategy)(nil) //readOnly{kapi.Scheme}

//type readOnly struct{ runtime.ObjectTyper }
//
//func (readOnly) PrepareForCreate(ctx kapi.Context, obj runtime.Object) {}
//func (readOnly) Canonicalize(obj runtime.Object)                       {}
//func (readOnly) NamespaceScoped() bool                                 { return false }
//func (readOnly) GenerateName(base string) string                       { return base }
//func (readOnly) Validate(ctx kapi.Context, obj runtime.Object) field.ErrorList {
//	return field.ErrorList{field.Invalid(field.NewPath(""), obj, "object is immutable")}
//}
