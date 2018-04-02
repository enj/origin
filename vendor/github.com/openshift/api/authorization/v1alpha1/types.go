package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authorizationv1 "github.com/openshift/api/authorization/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessRestriction is used to guard specific actions without invasive changes to the cluster's default RBAC policy.
// It supports either a whitelist or a blacklist based restriction.  It never grants any privileges - it can only be
// used to take privileges away.
type AccessRestriction struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Spec defines when this restriction is imposed and how to satisfy it.
	Spec AccessRestrictionSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}

// AccessRestrictionSpec holds the matching requirements.
// MatchAttributes is required.
// One of AllowedSubjects or DeniedSubjects must be specified.
type AccessRestrictionSpec struct {
	// If these rules cover the current request, then this restriction applies.
	// If AllowedSubjects is set, then only those subjects can perform the matching actions.
	// If DeniedSubjects is set, then only those subjects are restricted from performing the matching actions.
	// Required.
	MatchAttributes []rbacv1.PolicyRule `json:"matchAttributes" protobuf:"bytes,1,opt,name=matchAttributes"`

	// The whitelist of subjects that are allowed to perform the actions defined by MatchAttributes.
	// Note that this only prevents a denial due to the access restriction.
	// The subject must still have a matching RBAC binding to actually perform the current action.
	AllowedSubjects []SubjectMatcher `json:"allowedSubjects,omitempty" protobuf:"bytes,2,opt,name=allowedSubjects"`

	// The blacklist of subjects that are not allowed to perform the actions defined by MatchAttributes.
	// This restriction is processed before all RBAC data, and thus will reject actions that RBAC may otherwise permit.
	DeniedSubjects []SubjectMatcher `json:"deniedSubjects,omitempty" protobuf:"bytes,3,opt,name=deniedSubjects"`
}

// SubjectMatcher defines how an access restriction matches against the current user or service account or group.
// Exactly one field must be non-nil.
type SubjectMatcher struct {
	// UserRestriction matches against user or service account subjects.
	// Use system:serviceaccount:NAMESPACE:NAME to target a specific service account.
	UserRestriction *authorizationv1.UserRestriction `json:"userRestriction,omitempty" protobuf:"bytes,1,opt,name=userRestriction"`

	// GroupRestriction matches against group subjects.
	// Use system:serviceaccount:NAMESPACE to target all service accounts in a specific namespace.
	// Use system:serviceaccounts to target all service accounts.
	GroupRestriction *authorizationv1.GroupRestriction `json:"groupRestriction,omitempty" protobuf:"bytes,2,opt,name=groupRestriction"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessRestrictionList is a collection of AccessRestrictions
type AccessRestrictionList struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Items is a list of AccessRestriction objects.
	Items []AccessRestriction `json:"items" protobuf:"bytes,2,rep,name=items"`
}
