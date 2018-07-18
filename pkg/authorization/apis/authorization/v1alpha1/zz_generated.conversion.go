// +build !ignore_autogenerated_openshift

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	authorization_v1 "github.com/openshift/api/authorization/v1"
	v1alpha1 "github.com/openshift/api/authorization/v1alpha1"
	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	v1 "k8s.io/api/rbac/v1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	rbac "k8s.io/kubernetes/pkg/apis/rbac"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(scheme *runtime.Scheme) error {
	return scheme.AddGeneratedConversionFuncs(
		Convert_v1alpha1_AccessRestriction_To_authorization_AccessRestriction,
		Convert_authorization_AccessRestriction_To_v1alpha1_AccessRestriction,
		Convert_v1alpha1_AccessRestrictionList_To_authorization_AccessRestrictionList,
		Convert_authorization_AccessRestrictionList_To_v1alpha1_AccessRestrictionList,
		Convert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec,
		Convert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec,
		Convert_v1alpha1_SubjectMatcher_To_authorization_SubjectMatcher,
		Convert_authorization_SubjectMatcher_To_v1alpha1_SubjectMatcher,
	)
}

func autoConvert_v1alpha1_AccessRestriction_To_authorization_AccessRestriction(in *v1alpha1.AccessRestriction, out *authorization.AccessRestriction, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_AccessRestriction_To_authorization_AccessRestriction is an autogenerated conversion function.
func Convert_v1alpha1_AccessRestriction_To_authorization_AccessRestriction(in *v1alpha1.AccessRestriction, out *authorization.AccessRestriction, s conversion.Scope) error {
	return autoConvert_v1alpha1_AccessRestriction_To_authorization_AccessRestriction(in, out, s)
}

func autoConvert_authorization_AccessRestriction_To_v1alpha1_AccessRestriction(in *authorization.AccessRestriction, out *v1alpha1.AccessRestriction, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	return nil
}

// Convert_authorization_AccessRestriction_To_v1alpha1_AccessRestriction is an autogenerated conversion function.
func Convert_authorization_AccessRestriction_To_v1alpha1_AccessRestriction(in *authorization.AccessRestriction, out *v1alpha1.AccessRestriction, s conversion.Scope) error {
	return autoConvert_authorization_AccessRestriction_To_v1alpha1_AccessRestriction(in, out, s)
}

func autoConvert_v1alpha1_AccessRestrictionList_To_authorization_AccessRestrictionList(in *v1alpha1.AccessRestrictionList, out *authorization.AccessRestrictionList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]authorization.AccessRestriction)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1alpha1_AccessRestrictionList_To_authorization_AccessRestrictionList is an autogenerated conversion function.
func Convert_v1alpha1_AccessRestrictionList_To_authorization_AccessRestrictionList(in *v1alpha1.AccessRestrictionList, out *authorization.AccessRestrictionList, s conversion.Scope) error {
	return autoConvert_v1alpha1_AccessRestrictionList_To_authorization_AccessRestrictionList(in, out, s)
}

func autoConvert_authorization_AccessRestrictionList_To_v1alpha1_AccessRestrictionList(in *authorization.AccessRestrictionList, out *v1alpha1.AccessRestrictionList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1alpha1.AccessRestriction)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_authorization_AccessRestrictionList_To_v1alpha1_AccessRestrictionList is an autogenerated conversion function.
func Convert_authorization_AccessRestrictionList_To_v1alpha1_AccessRestrictionList(in *authorization.AccessRestrictionList, out *v1alpha1.AccessRestrictionList, s conversion.Scope) error {
	return autoConvert_authorization_AccessRestrictionList_To_v1alpha1_AccessRestrictionList(in, out, s)
}

func autoConvert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec(in *v1alpha1.AccessRestrictionSpec, out *authorization.AccessRestrictionSpec, s conversion.Scope) error {
	out.MatchAttributes = *(*[]rbac.PolicyRule)(unsafe.Pointer(&in.MatchAttributes))
	out.AllowedSubjects = *(*[]authorization.SubjectMatcher)(unsafe.Pointer(&in.AllowedSubjects))
	out.DeniedSubjects = *(*[]authorization.SubjectMatcher)(unsafe.Pointer(&in.DeniedSubjects))
	return nil
}

// Convert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec is an autogenerated conversion function.
func Convert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec(in *v1alpha1.AccessRestrictionSpec, out *authorization.AccessRestrictionSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_AccessRestrictionSpec_To_authorization_AccessRestrictionSpec(in, out, s)
}

func autoConvert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec(in *authorization.AccessRestrictionSpec, out *v1alpha1.AccessRestrictionSpec, s conversion.Scope) error {
	out.MatchAttributes = *(*[]v1.PolicyRule)(unsafe.Pointer(&in.MatchAttributes))
	out.AllowedSubjects = *(*[]v1alpha1.SubjectMatcher)(unsafe.Pointer(&in.AllowedSubjects))
	out.DeniedSubjects = *(*[]v1alpha1.SubjectMatcher)(unsafe.Pointer(&in.DeniedSubjects))
	return nil
}

// Convert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec is an autogenerated conversion function.
func Convert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec(in *authorization.AccessRestrictionSpec, out *v1alpha1.AccessRestrictionSpec, s conversion.Scope) error {
	return autoConvert_authorization_AccessRestrictionSpec_To_v1alpha1_AccessRestrictionSpec(in, out, s)
}

func autoConvert_v1alpha1_SubjectMatcher_To_authorization_SubjectMatcher(in *v1alpha1.SubjectMatcher, out *authorization.SubjectMatcher, s conversion.Scope) error {
	out.UserRestriction = (*authorization.UserRestriction)(unsafe.Pointer(in.UserRestriction))
	out.GroupRestriction = (*authorization.GroupRestriction)(unsafe.Pointer(in.GroupRestriction))
	return nil
}

// Convert_v1alpha1_SubjectMatcher_To_authorization_SubjectMatcher is an autogenerated conversion function.
func Convert_v1alpha1_SubjectMatcher_To_authorization_SubjectMatcher(in *v1alpha1.SubjectMatcher, out *authorization.SubjectMatcher, s conversion.Scope) error {
	return autoConvert_v1alpha1_SubjectMatcher_To_authorization_SubjectMatcher(in, out, s)
}

func autoConvert_authorization_SubjectMatcher_To_v1alpha1_SubjectMatcher(in *authorization.SubjectMatcher, out *v1alpha1.SubjectMatcher, s conversion.Scope) error {
	out.UserRestriction = (*authorization_v1.UserRestriction)(unsafe.Pointer(in.UserRestriction))
	out.GroupRestriction = (*authorization_v1.GroupRestriction)(unsafe.Pointer(in.GroupRestriction))
	return nil
}

// Convert_authorization_SubjectMatcher_To_v1alpha1_SubjectMatcher is an autogenerated conversion function.
func Convert_authorization_SubjectMatcher_To_v1alpha1_SubjectMatcher(in *authorization.SubjectMatcher, out *v1alpha1.SubjectMatcher, s conversion.Scope) error {
	return autoConvert_authorization_SubjectMatcher_To_v1alpha1_SubjectMatcher(in, out, s)
}
