package api

import (
	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/sets"
)

func addConversionFuncs(scheme *runtime.Scheme) error {
	if err := scheme.AddConversionFuncs(
		Convert_api_ClusterRole_To_rbac_ClusterRole,
		Convert_api_Role_To_rbac_Role,
		Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding,
		Convert_api_RoleBinding_To_rbac_RoleBinding,
		Convert_rbac_ClusterRole_To_api_ClusterRole,
		Convert_rbac_Role_To_api_Role,
		Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding,
		Convert_rbac_RoleBinding_To_api_RoleBinding,
	); err != nil { // If one of the conversion functions is malformed, detect it immediately.
		return err
	}
	return nil
}

func Convert_api_ClusterRole_To_rbac_ClusterRole(in *ClusterRole) *rbac.ClusterRole {
	return &rbac.ClusterRole{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertOriginPolicyRule(in.Rules),
	}
}

func Convert_api_Role_To_rbac_Role(in *Role) *rbac.Role {
	return &rbac.Role{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertOriginPolicyRule(in.Rules),
	}
}

func Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding(in *ClusterRoleBinding) *rbac.ClusterRoleBinding {
	return &rbac.ClusterRoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertOriginSubjects(in.Subjects),
		RoleRef:    convertOriginRoleRef(&in.RoleRef),
	}
}

func Convert_api_RoleBinding_To_rbac_RoleBinding(in *RoleBinding) *rbac.RoleBinding {
	return &rbac.RoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertOriginSubjects(in.Subjects),
		RoleRef:    convertOriginRoleRef(&in.RoleRef),
	}
}

func convertOriginPolicyRule(in []PolicyRule) []rbac.PolicyRule {
	rules := make([]rbac.PolicyRule, 0, len(in))
	for _, rule := range in {
		r := rbac.PolicyRule{
			APIGroups:       rule.APIGroups,
			Verbs:           rule.Verbs.List(),
			Resources:       rule.Resources.List(),
			ResourceNames:   rule.ResourceNames.List(),
			NonResourceURLs: rule.NonResourceURLs.List(),
		}
		rules = append(rules, r)
	}
	return rules
}

func convertOriginSubjects(in []api.ObjectReference) []rbac.Subject {
	subjects := make([]rbac.Subject, 0, len(in))
	for _, subject := range in {
		s := rbac.Subject{
			Kind:       subject.Kind,
			APIVersion: subject.APIVersion,
			Name:       subject.Name,
			Namespace:  subject.Namespace,
		}
		subjects = append(subjects, s)
	}
	return subjects
}

func convertOriginRoleRef(in *api.ObjectReference) rbac.RoleRef {
	return rbac.RoleRef{
		APIGroup: in.APIVersion,
		Kind:     in.Kind,
		Name:     in.Name,
	}
}

func Convert_rbac_ClusterRole_To_api_ClusterRole(in *rbac.ClusterRole) *ClusterRole {
	return &ClusterRole{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertRBACPolicyRules(in.Rules),
	}
}

func Convert_rbac_Role_To_api_Role(in *rbac.Role) *Role {
	return &Role{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertRBACPolicyRules(in.Rules),
	}
}

func Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding(in *rbac.ClusterRoleBinding) *ClusterRoleBinding {
	return &ClusterRoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertRBACSubjects(in.Subjects),
		RoleRef:    convertRBACRoleRef(&in.RoleRef),
	}
}

func Convert_rbac_RoleBinding_To_api_RoleBinding(in *rbac.RoleBinding) *RoleBinding {
	return &RoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertRBACSubjects(in.Subjects),
		RoleRef:    convertRBACRoleRef(&in.RoleRef),
	}
}

func convertRBACSubjects(in []rbac.Subject) []api.ObjectReference {
	subjects := make([]api.ObjectReference, 0, len(in))
	for _, subject := range in {
		s := api.ObjectReference{
			Kind:       subject.Kind,
			APIVersion: subject.APIVersion,
			Name:       subject.Name,
			Namespace:  subject.Namespace,
		}
		subjects = append(subjects, s)
	}
	return subjects
}

func convertRBACRoleRef(in *rbac.RoleRef) api.ObjectReference {
	return api.ObjectReference{
		APIVersion: in.APIGroup,
		Kind:       in.Kind,
		Name:       in.Name,
	}
}

func convertRBACPolicyRules(in []rbac.PolicyRule) []PolicyRule {
	rules := make([]PolicyRule, 0, len(in))
	for _, rule := range in {
		r := PolicyRule{
			APIGroups:       rule.APIGroups,
			Verbs:           sets.NewString(rule.Verbs...),
			Resources:       sets.NewString(rule.Resources...),
			ResourceNames:   sets.NewString(rule.ResourceNames...),
			NonResourceURLs: sets.NewString(rule.NonResourceURLs...),
		}
		rules = append(rules, r)
	}
	return rules
}
