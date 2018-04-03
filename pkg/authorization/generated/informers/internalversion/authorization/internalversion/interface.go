// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	internalinterfaces "github.com/openshift/origin/pkg/authorization/generated/informers/internalversion/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// AccessRestrictions returns a AccessRestrictionInformer.
	AccessRestrictions() AccessRestrictionInformer
	// ClusterPolicies returns a ClusterPolicyInformer.
	ClusterPolicies() ClusterPolicyInformer
	// ClusterPolicyBindings returns a ClusterPolicyBindingInformer.
	ClusterPolicyBindings() ClusterPolicyBindingInformer
	// ClusterRoles returns a ClusterRoleInformer.
	ClusterRoles() ClusterRoleInformer
	// ClusterRoleBindings returns a ClusterRoleBindingInformer.
	ClusterRoleBindings() ClusterRoleBindingInformer
	// Policies returns a PolicyInformer.
	Policies() PolicyInformer
	// PolicyBindings returns a PolicyBindingInformer.
	PolicyBindings() PolicyBindingInformer
	// Roles returns a RoleInformer.
	Roles() RoleInformer
	// RoleBindings returns a RoleBindingInformer.
	RoleBindings() RoleBindingInformer
	// RoleBindingRestrictions returns a RoleBindingRestrictionInformer.
	RoleBindingRestrictions() RoleBindingRestrictionInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// AccessRestrictions returns a AccessRestrictionInformer.
func (v *version) AccessRestrictions() AccessRestrictionInformer {
	return &accessRestrictionInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterPolicies returns a ClusterPolicyInformer.
func (v *version) ClusterPolicies() ClusterPolicyInformer {
	return &clusterPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterPolicyBindings returns a ClusterPolicyBindingInformer.
func (v *version) ClusterPolicyBindings() ClusterPolicyBindingInformer {
	return &clusterPolicyBindingInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterRoles returns a ClusterRoleInformer.
func (v *version) ClusterRoles() ClusterRoleInformer {
	return &clusterRoleInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterRoleBindings returns a ClusterRoleBindingInformer.
func (v *version) ClusterRoleBindings() ClusterRoleBindingInformer {
	return &clusterRoleBindingInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// Policies returns a PolicyInformer.
func (v *version) Policies() PolicyInformer {
	return &policyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// PolicyBindings returns a PolicyBindingInformer.
func (v *version) PolicyBindings() PolicyBindingInformer {
	return &policyBindingInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Roles returns a RoleInformer.
func (v *version) Roles() RoleInformer {
	return &roleInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// RoleBindings returns a RoleBindingInformer.
func (v *version) RoleBindings() RoleBindingInformer {
	return &roleBindingInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// RoleBindingRestrictions returns a RoleBindingRestrictionInformer.
func (v *version) RoleBindingRestrictions() RoleBindingRestrictionInformer {
	return &roleBindingRestrictionInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
