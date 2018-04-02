// +build !ignore_autogenerated

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	authorization_v1 "github.com/openshift/api/authorization/v1"
	v1 "k8s.io/api/rbac/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessRestriction) DeepCopyInto(out *AccessRestriction) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessRestriction.
func (in *AccessRestriction) DeepCopy() *AccessRestriction {
	if in == nil {
		return nil
	}
	out := new(AccessRestriction)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AccessRestriction) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessRestrictionList) DeepCopyInto(out *AccessRestrictionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AccessRestriction, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessRestrictionList.
func (in *AccessRestrictionList) DeepCopy() *AccessRestrictionList {
	if in == nil {
		return nil
	}
	out := new(AccessRestrictionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AccessRestrictionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessRestrictionSpec) DeepCopyInto(out *AccessRestrictionSpec) {
	*out = *in
	if in.MatchAttributes != nil {
		in, out := &in.MatchAttributes, &out.MatchAttributes
		*out = make([]v1.PolicyRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AllowedSubjects != nil {
		in, out := &in.AllowedSubjects, &out.AllowedSubjects
		*out = make([]SubjectMatcher, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.DeniedSubjects != nil {
		in, out := &in.DeniedSubjects, &out.DeniedSubjects
		*out = make([]SubjectMatcher, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessRestrictionSpec.
func (in *AccessRestrictionSpec) DeepCopy() *AccessRestrictionSpec {
	if in == nil {
		return nil
	}
	out := new(AccessRestrictionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SubjectMatcher) DeepCopyInto(out *SubjectMatcher) {
	*out = *in
	if in.UserRestriction != nil {
		in, out := &in.UserRestriction, &out.UserRestriction
		if *in == nil {
			*out = nil
		} else {
			*out = new(authorization_v1.UserRestriction)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.GroupRestriction != nil {
		in, out := &in.GroupRestriction, &out.GroupRestriction
		if *in == nil {
			*out = nil
		} else {
			*out = new(authorization_v1.GroupRestriction)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SubjectMatcher.
func (in *SubjectMatcher) DeepCopy() *SubjectMatcher {
	if in == nil {
		return nil
	}
	out := new(SubjectMatcher)
	in.DeepCopyInto(out)
	return out
}
