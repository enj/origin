package v1

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch/versioned"
)

const (
	GroupName       = "requestlimit.project.openshift.io"
	LegacyGroupName = ""
)

var (
	SchemeGroupVersion       = unversioned.GroupVersion{Group: GroupName, Version: "v1"}
	LegacySchemeGroupVersion = unversioned.GroupVersion{Group: LegacyGroupName, Version: "v1"}

	LegacySchemeBuilder    = runtime.NewSchemeBuilder(addLegacyKnownTypes)
	AddToSchemeInCoreGroup = LegacySchemeBuilder.AddToScheme

	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

// Adds the list of known types to api.Scheme.
func addLegacyKnownTypes(scheme *runtime.Scheme) error {
	types := []runtime.Object{
		&ProjectRequestLimitConfig{},
	}
	scheme.AddKnownTypes(LegacySchemeGroupVersion, types...)
	return nil
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	types := []runtime.Object{
		&ProjectRequestLimitConfig{},
	}
	scheme.AddKnownTypes(SchemeGroupVersion,
		append(types,
			&unversioned.Status{}, // TODO: revisit in 1.6 when Status is actually registered as unversioned
			&kapi.ListOptions{},
			&kapi.DeleteOptions{},
			&kapi.ExportOptions{},
		)...,
	)
	versioned.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
